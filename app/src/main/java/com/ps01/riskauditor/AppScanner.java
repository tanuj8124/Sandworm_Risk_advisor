/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 *
 * On-device inventory of installed apps. The package-enumeration and APK-hashing
 * approach follows Hypatia (https://github.com/divested-mobile/hypatia,
 * MainActivity.java / MalwareScanner.java, AGPL-3.0): walk
 * PackageManager.getInstalledApplications() and read ApplicationInfo.sourceDir,
 * hashing the base APK with MessageDigest. Hypatia stops at the hash; this class adds
 * permissions, protection levels and live special-access state.
 */
package com.ps01.riskauditor;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.AppOpsManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.accessibility.AccessibilityManager;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AppScanner {

    private static final String ACCESSIBILITY_ACTION = "android.accessibilityservice.AccessibilityService";
    private static final String NOTIF_LISTENER_ACTION = "android.service.notification.NotificationListenerService";
    private static final String DEVICE_ADMIN_ACTION = "android.app.action.DEVICE_ADMIN_ENABLED";

    private static final String P_BIND_ACC = "android.permission.BIND_ACCESSIBILITY_SERVICE";
    private static final String P_BIND_NOTIF = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE";
    private static final String P_BIND_ADMIN = "android.permission.BIND_DEVICE_ADMIN";
    private static final String P_OVERLAY = "android.permission.SYSTEM_ALERT_WINDOW";
    private static final String P_INSTALL = "android.permission.REQUEST_INSTALL_PACKAGES";
    private static final String P_USAGE = "android.permission.PACKAGE_USAGE_STATS";
    private static final String P_ALL_FILES = "android.permission.MANAGE_EXTERNAL_STORAGE";

    /** App stores we treat as a trusted install source. Anything else (or nothing) = sideloaded. */
    public static final Set<String> KNOWN_STORES = new HashSet<>(Arrays.asList(
            "com.android.vending", "com.google.android.feedback",
            "com.amazon.venezia", "com.sec.android.app.samsungapps",
            "com.huawei.appmarket", "com.xiaomi.market", "com.xiaomi.mipicks",
            "com.oppo.market", "com.heytap.market", "com.bbk.appstore",
            "org.fdroid.fdroid", "org.fdroid.basic", "com.aurora.store"));

    private final Context ctx;
    private final PackageManager pm;
    private final Map<String, String> protectionCache = new HashMap<>();

    /** Device-wide special-access state, gathered once per scan. */
    private static class SystemState {
        final Set<String> accEnabled = new HashSet<>(), accDeclared = new HashSet<>();
        final Set<String> adminActive = new HashSet<>(), adminDeclared = new HashSet<>();
        final Set<String> notifEnabled = new HashSet<>(), notifDeclared = new HashSet<>();
    }

    public AppScanner(Context context) {
        this.ctx = context.getApplicationContext();
        this.pm = ctx.getPackageManager();
    }

    // ------------------------------------------------------------------ public API

    public List<AppReport> scanAll(boolean includeSystem) {
        SystemState st = readSystemState();
        List<AppReport> out = new ArrayList<>();
        List<ApplicationInfo> apps = pm.getInstalledApplications(0);
        for (ApplicationInfo ai : apps) {
            if (ai.packageName.equals(ctx.getPackageName())) continue;
            boolean system = (ai.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
            if (system && !includeSystem) continue;
            AppReport r = build(ai.packageName, st);
            if (r != null) out.add(r);
        }
        Collections.sort(out, (a, b) -> b.score != a.score ? b.score - a.score
                : String.CASE_INSENSITIVE_ORDER.compare(a.label, b.label));
        return out;
    }

    /** Scan a single package (detail screen, install monitor). Returns null if it is gone. */
    public AppReport scanPackage(String packageName) {
        return build(packageName, readSystemState());
    }

    // ------------------------------------------------------------------ building a report

    private AppReport build(String pkg, SystemState st) {
        PackageInfo pi;
        int flags = PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES
                | PackageManager.GET_RECEIVERS | PackageManager.GET_PROVIDERS;
        try {
            pi = pm.getPackageInfo(pkg, flags);
        } catch (PackageManager.NameNotFoundException e) {
            return null;
        } catch (RuntimeException tooLarge) {
            // Very large apps can overflow the binder buffer; fall back to permissions only.
            try {
                pi = pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS);
            } catch (Exception e) {
                return null;
            }
        }
        ApplicationInfo ai = pi.applicationInfo;
        if (ai == null) return null;

        AppReport r = new AppReport();
        r.packageName = pkg;
        r.label = String.valueOf(pm.getApplicationLabel(ai));
        r.versionName = pi.versionName == null ? "?" : pi.versionName;
        r.versionCode = Build.VERSION.SDK_INT >= 28 ? pi.getLongVersionCode() : pi.versionCode;
        r.firstInstallTime = pi.firstInstallTime;
        r.lastUpdateTime = pi.lastUpdateTime;
        r.targetSdk = ai.targetSdkVersion;
        r.isSystem = (ai.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
        r.apkPath = ai.sourceDir;
        if (Build.VERSION.SDK_INT >= 26) r.playCategory = ai.category;
        r.debuggable = (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        r.cleartextAllowed = (ai.flags & ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0;
        r.exportedUnprotected = countExportedUnprotected(pi);

        // Installer source
        r.installerPackage = installerOf(pkg);
        r.installerLabel = labelOrNull(r.installerPackage);
        if (r.installerLabel == null) {
            r.installerLabel = r.installerPackage == null ? "Unknown (sideloaded / adb)" : r.installerPackage;
        }
        r.sideloaded = !r.isSystem && (r.installerPackage == null || !KNOWN_STORES.contains(r.installerPackage));

        // Declared vs granted uses-permissions
        if (pi.requestedPermissions != null) {
            for (int i = 0; i < pi.requestedPermissions.length; i++) {
                String name = pi.requestedPermissions[i];
                boolean granted = pi.requestedPermissionsFlags != null
                        && (pi.requestedPermissionsFlags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0;
                r.declared.add(name);
                if (granted) r.granted.add(name);
            }
        }

        // Special access — combine manifest declarations with live system state
        int uid = ai.uid;
        r.accessibilityDeclared = st.accDeclared.contains(pkg);
        r.accessibilityEnabled = st.accEnabled.contains(pkg);
        r.adminDeclared = st.adminDeclared.contains(pkg);
        r.adminActive = st.adminActive.contains(pkg);
        r.notifListenerDeclared = st.notifDeclared.contains(pkg);
        r.notifListenerEnabled = st.notifEnabled.contains(pkg);

        r.overlayDeclared = r.has(P_OVERLAY);
        r.overlayGranted = r.overlayDeclared && opGranted(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, uid, pkg, r.hasGranted(P_OVERLAY));
        r.installDeclared = r.has(P_INSTALL);
        r.installGranted = r.installDeclared && opGranted("android:request_install_packages", uid, pkg, false);
        r.usageDeclared = r.has(P_USAGE);
        r.usageGranted = r.usageDeclared && opGranted(AppOpsManager.OPSTR_GET_USAGE_STATS, uid, pkg, r.hasGranted(P_USAGE));
        r.allFilesDeclared = r.has(P_ALL_FILES);
        r.allFilesGranted = r.allFilesDeclared && Build.VERSION.SDK_INT >= 30
                && opGranted("android:manage_external_storage", uid, pkg, r.hasGranted(P_ALL_FILES));

        // Reflect app-op results in the granted set so categorisation is accurate
        setGranted(r, P_OVERLAY, r.overlayGranted);
        setGranted(r, P_INSTALL, r.installGranted);
        setGranted(r, P_USAGE, r.usageGranted);
        setGranted(r, P_ALL_FILES, r.allFilesGranted);

        // Bound services are declared on components, not as uses-permission: add them so they show up
        if (r.accessibilityDeclared) addSynthetic(r, P_BIND_ACC, r.accessibilityEnabled);
        if (r.notifListenerDeclared) addSynthetic(r, P_BIND_NOTIF, r.notifListenerEnabled);
        if (r.adminDeclared) addSynthetic(r, P_BIND_ADMIN, r.adminActive);

        for (String name : r.declared) {
            PermissionCatalog.Entry e = PermissionCatalog.get(name);
            r.perms.add(new AppReport.Perm(name, r.granted.contains(name), protectionOf(name),
                    e == null ? null : e.category));
        }

        // Hidden icon: user apps with no launcher entry can't be found in the app drawer
        r.hasLauncherIcon = pm.getLaunchIntentForPackage(pkg) != null
                || (Build.VERSION.SDK_INT >= 21 && pm.getLeanbackLaunchIntentForPackage(pkg) != null);
        try {
            r.isKeyboard = !pm.queryIntentServices(new Intent("android.view.InputMethod").setPackage(pkg), 0).isEmpty();
        } catch (Exception ignored) {
        }
        // Suspicious servers seen by the network monitor (persisted)
        r.netFlags.putAll(NetLog.flaggedFor(ctx, pkg));

        // AI check (antimalwareapp model): manifest permissions + intent-filter actions
        if (pi.requestedPermissions != null) r.manifestPermissions.addAll(Arrays.asList(pi.requestedPermissions));
        r.manifestActions.addAll(ManifestReader.readActions(r.apkPath));
        MlScanner.Result ml = MlScanner.get(ctx).predict(r.manifestPermissions, r.manifestActions);
        r.mlProbability = ml.probability;
        r.mlMatched = ml.matched;
        r.mlVerdict = ml.verdict;

        SnapshotStore.diff(ctx, r);
        RiskEngine.evaluate(r);
        return r;
    }

    private static void setGranted(AppReport r, String perm, boolean granted) {
        if (!r.declared.contains(perm)) return;
        if (granted) r.granted.add(perm);
        else r.granted.remove(perm);
    }

    private static void addSynthetic(AppReport r, String perm, boolean granted) {
        r.declared.add(perm);
        setGranted(r, perm, granted);
    }

    // ------------------------------------------------------------------ helpers

    private SystemState readSystemState() {
        SystemState st = new SystemState();

        // Enabled accessibility services (two sources, union)
        try {
            String s = Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            addComponentPackages(s, st.accEnabled);
        } catch (Exception ignored) {
        }
        try {
            AccessibilityManager am = (AccessibilityManager) ctx.getSystemService(Context.ACCESSIBILITY_SERVICE);
            if (am != null) {
                for (AccessibilityServiceInfo info : am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)) {
                    if (info.getResolveInfo() != null && info.getResolveInfo().serviceInfo != null) {
                        st.accEnabled.add(info.getResolveInfo().serviceInfo.packageName);
                    }
                }
            }
        } catch (Exception ignored) {
        }

        // Enabled notification listeners
        try {
            String s = Settings.Secure.getString(ctx.getContentResolver(), "enabled_notification_listeners");
            addComponentPackages(s, st.notifEnabled);
        } catch (Exception ignored) {
        }

        // Active device admins
        try {
            DevicePolicyManager dpm = (DevicePolicyManager) ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            List<ComponentName> admins = dpm == null ? null : dpm.getActiveAdmins();
            if (admins != null) for (ComponentName cn : admins) st.adminActive.add(cn.getPackageName());
        } catch (Exception ignored) {
        }

        // Declared (whether or not enabled)
        collectServices(ACCESSIBILITY_ACTION, P_BIND_ACC, st.accDeclared);
        collectServices(NOTIF_LISTENER_ACTION, P_BIND_NOTIF, st.notifDeclared);
        try {
            for (ResolveInfo ri : pm.queryBroadcastReceivers(new Intent(DEVICE_ADMIN_ACTION), PackageManager.GET_META_DATA)) {
                ActivityInfo a = ri.activityInfo;
                if (a != null && (a.permission == null || P_BIND_ADMIN.equals(a.permission))) st.adminDeclared.add(a.packageName);
            }
        } catch (Exception ignored) {
        }
        // Enabled implies declared
        st.accDeclared.addAll(st.accEnabled);
        st.notifDeclared.addAll(st.notifEnabled);
        st.adminDeclared.addAll(st.adminActive);
        return st;
    }

    private void collectServices(String action, String bindPerm, Set<String> out) {
        try {
            for (ResolveInfo ri : pm.queryIntentServices(new Intent(action), PackageManager.GET_META_DATA)) {
                ServiceInfo s = ri.serviceInfo;
                if (s != null && (s.permission == null || bindPerm.equals(s.permission))) out.add(s.packageName);
            }
        } catch (Exception ignored) {
        }
    }

    private static void addComponentPackages(String setting, Set<String> out) {
        if (TextUtils.isEmpty(setting)) return;
        for (String part : setting.split(":")) {
            ComponentName cn = ComponentName.unflattenFromString(part.trim());
            if (cn != null) out.add(cn.getPackageName());
        }
    }

    private boolean opGranted(String op, int uid, String pkg, boolean fallbackIfDefault) {
        try {
            AppOpsManager aom = (AppOpsManager) ctx.getSystemService(Context.APP_OPS_SERVICE);
            int mode = Build.VERSION.SDK_INT >= 29
                    ? aom.unsafeCheckOpNoThrow(op, uid, pkg)
                    : aom.checkOpNoThrow(op, uid, pkg);
            if (mode == AppOpsManager.MODE_ALLOWED) return true;
            if (mode == AppOpsManager.MODE_DEFAULT) return fallbackIfDefault;
            return false;
        } catch (Exception e) {
            return fallbackIfDefault;
        }
    }

    private String installerOf(String pkg) {
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                InstallSourceInfo isi = pm.getInstallSourceInfo(pkg);
                String p = isi.getInstallingPackageName();
                return p != null ? p : isi.getInitiatingPackageName();
            }
            return pm.getInstallerPackageName(pkg);
        } catch (Exception e) {
            return null;
        }
    }

    private String labelOrNull(String pkg) {
        if (pkg == null) return null;
        if ("com.android.shell".equals(pkg)) return "ADB shell (sideloaded)";
        try {
            return String.valueOf(pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)));
        } catch (Exception e) {
            return null;
        }
    }

    private String protectionOf(String name) {
        String cached = protectionCache.get(name);
        if (cached != null) return cached;
        String result;
        try {
            PermissionInfo pi = pm.getPermissionInfo(name, 0);
            int base, flags;
            if (Build.VERSION.SDK_INT >= 28) {
                base = pi.getProtection();
                flags = pi.getProtectionFlags();
            } else {
                base = pi.protectionLevel & PermissionInfo.PROTECTION_MASK_BASE;
                flags = pi.protectionLevel & ~PermissionInfo.PROTECTION_MASK_BASE;
            }
            if (PermissionCatalog.isSpecialAccess(name)
                    || ((flags & PermissionInfo.PROTECTION_FLAG_APPOP) != 0 && base != PermissionInfo.PROTECTION_DANGEROUS)) {
                result = "special";
            } else if (base == PermissionInfo.PROTECTION_NORMAL) {
                result = "normal";
            } else if (base == PermissionInfo.PROTECTION_DANGEROUS) {
                result = "dangerous";
            } else if (base == PermissionInfo.PROTECTION_SIGNATURE || base == 3 /* signatureOrSystem */) {
                result = "signature";
            } else {
                result = "internal";
            }
        } catch (PackageManager.NameNotFoundException e) {
            result = PermissionCatalog.isSpecialAccess(name) ? "special" : "unknown";
        } catch (Exception e) {
            result = "unknown";
        }
        protectionCache.put(name, result);
        return result;
    }

    private static int countExportedUnprotected(PackageInfo pi) {
        int n = 0;
        if (pi.services != null) for (ServiceInfo s : pi.services) if (s.exported && s.permission == null) n++;
        if (pi.receivers != null) for (ActivityInfo a : pi.receivers) if (a.exported && a.permission == null) n++;
        if (pi.providers != null) for (ProviderInfo p : pi.providers) {
            if (p.exported && p.readPermission == null && p.writePermission == null) n++;
        }
        return n;
    }

    /** SHA-256 of the base APK, computed locally (hashing pattern from Hypatia's MalwareScanner). */
    public static String sha256(String path) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new BufferedInputStream(new FileInputStream(new File(path)))) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest()) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
