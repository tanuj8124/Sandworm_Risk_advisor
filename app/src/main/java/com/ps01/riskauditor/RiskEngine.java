/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 *
 * Explainable rule-based risk score (0–100). Every point added comes with a
 * plain-language reason and a suggested fix. The weights are documented in RUBRIC.md —
 * keep the two in sync.
 */
package com.ps01.riskauditor;

import com.ps01.riskauditor.AppReport.Fix;
import com.ps01.riskauditor.AppReport.Reason;
import com.ps01.riskauditor.PermissionCatalog.Category;

import android.content.pm.ApplicationInfo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public final class RiskEngine {

    // ---- Special access weights (live state vs merely declared) ----
    static final int ACC_ON = 30, ACC_DECL = 10;
    static final int ADMIN_ON = 25, ADMIN_DECL = 8;
    static final int NOTIF_ON = 20, NOTIF_DECL = 7;
    static final int OVERLAY_ON = 15, OVERLAY_DECL = 6;
    static final int INSTALL_ON = 12, INSTALL_DECL = 5;
    static final int USAGE_ON = 8, USAGE_DECL = 3;

    // ---- Combination / context rules ----
    static final int C_SMS_TROJAN = 25;      // SMS read + internet + boot + sideloaded
    static final int C_ACC_OVERLAY = 25;     // accessibility + overlay
    static final int C_ADMIN_NONSEC = 20;    // device admin on a non-security / non-MDM app (10 if only declared)
    static final int C_NOTIF_NET = 10;       // notification listener ON + internet
    static final int C_DROPPER = 10;         // install-packages + sideloaded + internet
    static final int C_MISMATCH = 20;        // simple utility holding SMS / contacts / call log / accessibility
    static final int C_UPDATE_ADDED = 10;    // update added sensitive permissions
    static final int C_SIDELOADED = 5;
    static final int C_OLD_TARGET = 10;      // targetSdk < 23 (gets dangerous perms without asking)
    static final int C_DEBUGGABLE = 5;
    static final int C_CLEARTEXT = 3;
    static final int C_EXPORTED = 3;         // >= 5 exported components without a permission
    static final int C_HIDDEN_ICON = 8;      // user app with no launcher icon
    static final int C_NET_SMS_EXFIL = 15;   // reads SMS + seen contacting an exfil channel
    static final double SYSTEM_APP_FACTOR = 0.6;

    private static final String P = "android.permission.";

    /** Matched as whole words against "label + package" (dots treated as spaces). */
    private static final java.util.regex.Pattern UTILITY_WORDS = java.util.regex.Pattern.compile(
            "\\b(torch|flashlight|flash ?light|calculator|calc|wallpapers?|compass|ruler|qr|qrcode|"
            + "barcode|cleaner|booster|ringtones?|magnifier|notepad|converter|spirit ?level|bubble ?level)\\b");

    private static final List<String> SECURITY_WORDS = Arrays.asList(
            "security", "antivirus", "anti-virus", "mdm", "device policy", "intune", "airwatch",
            "workspace one", "find my", "findmy", "anti-theft", "antitheft", "mobileiron", "knox",
            "family link", "kaspersky", "avast", "bitdefender", "norton", "mcafee", "sophos", "eset");

    private RiskEngine() {
    }

    public static void evaluate(AppReport r) {
        r.reasons.clear();
        r.categoryPoints.clear();
        r.grantedCategories.clear();
        List<Reason> rs = new ArrayList<>();

        // ---------------- 01 Special access ----------------
        int special = 0;
        if (r.accessibilityEnabled) {
            special += add(rs, ACC_ON, "Accessibility service is ON: it can read everything on your screen and tap buttons for you. Banking trojans use this to steal passwords.", Fix.ACCESSIBILITY);
        } else if (r.accessibilityDeclared) {
            special += add(rs, ACC_DECL, "Contains an accessibility service (currently off). If you are asked to turn it on, it could read your screen.", Fix.NONE);
        }
        if (r.adminActive) {
            special += add(rs, ADMIN_ON, "Is an active device admin: it can lock or wipe the phone and stop you uninstalling it.", Fix.DEVICE_ADMIN);
        } else if (r.adminDeclared) {
            special += add(rs, ADMIN_DECL, "Can ask to become device admin (not active now).", Fix.NONE);
        }
        if (r.notifListenerEnabled) {
            special += add(rs, NOTIF_ON, "Can read all your notifications, including OTP codes and private messages.", Fix.NOTIFICATION_LISTENER);
        } else if (r.notifListenerDeclared) {
            special += add(rs, NOTIF_DECL, "Contains a notification reader (not enabled now).", Fix.NONE);
        }
        if (r.overlayGranted) {
            special += add(rs, OVERLAY_ON, "Allowed to draw over other apps: it can show fake login screens on top of your banking apps.", Fix.OVERLAY);
        } else if (r.overlayDeclared) {
            special += add(rs, OVERLAY_DECL, "Asks to draw over other apps (not allowed now).", Fix.NONE);
        }
        if (r.installGranted) {
            special += add(rs, INSTALL_ON, "Allowed to install other apps: it could download and install more malware.", Fix.UNKNOWN_SOURCES);
        } else if (r.installDeclared) {
            special += add(rs, INSTALL_DECL, "Asks to install other apps (not allowed now).", Fix.NONE);
        }
        if (r.usageGranted) {
            special += add(rs, USAGE_ON, "Has usage access: it can see which apps you open and when (e.g. to spot your banking app).", Fix.USAGE_ACCESS);
        } else if (r.usageDeclared) {
            special += add(rs, USAGE_DECL, "Asks for usage access (not allowed now).", Fix.NONE);
        }
        special = cap(rs, special, Category.SPECIAL.cap);
        r.categoryPoints.put(Category.SPECIAL, special);
        if (r.accessibilityEnabled || r.adminActive || r.notifListenerEnabled || r.overlayGranted
                || r.installGranted || r.usageGranted) {
            r.grantedCategories.add(Category.SPECIAL);
        }
        int total = special;

        // ---------------- 02–09 Runtime / install permissions by category ----------------
        for (Category c : Category.values()) {
            if (c == Category.SPECIAL) continue;
            double pts = 0;
            List<String> grantedTxt = new ArrayList<>();
            List<String> askedTxt = new ArrayList<>();
            for (AppReport.Perm p : r.perms) {
                if (p.category != c) continue;
                PermissionCatalog.Entry e = PermissionCatalog.get(p.name);
                if (e == null) continue;
                if (p.granted) {
                    pts += e.points;
                    grantedTxt.add(e.plain);
                } else {
                    pts += e.points * PermissionCatalog.DECLARED_FACTOR;
                    askedTxt.add(e.plain);
                }
            }
            if (!grantedTxt.isEmpty()) r.grantedCategories.add(c);
            int p = (int) Math.round(Math.min(pts, c.cap));
            if (p <= 0) continue;
            r.categoryPoints.put(c, p);
            total += p;
            StringBuilder sb = new StringBuilder();
            if (!grantedTxt.isEmpty()) {
                sb.append(c.title).append(": can ").append(joinPlain(grantedTxt)).append('.');
            }
            if (!askedTxt.isEmpty()) {
                if (sb.length() > 0) sb.append(' ');
                sb.append(grantedTxt.isEmpty() ? c.title + ": asks to " : "Also asks to ")
                        .append(joinPlain(askedTxt)).append(" (not granted yet).");
            }
            sb.append(" Risk: ").append(c.why).append('.');
            Fix fix = (c == Category.STORAGE && r.allFilesGranted) ? Fix.ALL_FILES
                    : (grantedTxt.isEmpty() ? Fix.NONE : Fix.APP_SETTINGS);
            rs.add(new Reason(p, sb.toString(), fix));
        }

        // ---------------- Combination rules ----------------
        boolean internet = r.has(P + "INTERNET");
        boolean smsRead = r.has(P + "READ_SMS") || r.has(P + "RECEIVE_SMS");
        boolean boot = r.has(P + "RECEIVE_BOOT_COMPLETED");

        if (smsRead && internet && boot && r.sideloaded) {
            total += add(rs, C_SMS_TROJAN, "Banking-trojan pattern: reads SMS, can send data online, restarts itself at boot, and was NOT installed from an app store.", Fix.UNINSTALL);
        }
        if ((r.accessibilityEnabled || r.accessibilityDeclared) && r.overlayDeclared) {
            total += add(rs, C_ACC_OVERLAY, "Dangerous combination: accessibility + drawing over apps. This is how overlay attacks steal banking logins.", Fix.UNINSTALL);
        }
        String hay = (r.label + " " + r.packageName).toLowerCase(Locale.ROOT);
        if ((r.adminActive || r.adminDeclared) && !containsAny(hay, SECURITY_WORDS)) {
            total += add(rs, r.adminActive ? C_ADMIN_NONSEC : C_ADMIN_NONSEC / 2,
                    "Wants device-admin control but does not look like a security or work (MDM) app.", Fix.DEVICE_ADMIN);
        }
        if (r.notifListenerEnabled && internet) {
            total += add(rs, C_NOTIF_NET, "Reads your notifications AND has internet access, so OTP codes could be sent off the phone.", Fix.NOTIFICATION_LISTENER);
        }
        if (r.installDeclared && r.sideloaded && internet) {
            total += add(rs, C_DROPPER, "Sideloaded app that can download and install other apps (dropper behaviour).", Fix.UNKNOWN_SOURCES);
        }

        // ---------------- Context mismatch ----------------
        String mismatch = contextMismatch(r, hay);
        if (mismatch != null) {
            total += add(rs, C_MISMATCH, mismatch, Fix.UNINSTALL);
        }

        // ---------------- Install source, update diff, manifest checks ----------------
        if (!r.addedOnUpdate.isEmpty()) {
            List<String> names = new ArrayList<>();
            for (String s : r.addedOnUpdate) names.add(s.substring(s.lastIndexOf('.') + 1));
            total += add(rs, C_UPDATE_ADDED, "Its latest update added new sensitive permissions: " + String.join(", ", names) + ".", Fix.APP_SETTINGS);
        }
        if (r.sideloaded) {
            total += add(rs, C_SIDELOADED, "Not installed from an app store (installer: " + r.installerLabel + "), so it was never reviewed.", Fix.NONE);
        }
        if (r.targetSdk > 0 && r.targetSdk < 23) {
            total += add(rs, C_OLD_TARGET, "Built for a very old Android version (target SDK " + r.targetSdk + "), so it gets dangerous permissions without asking you.", Fix.UNINSTALL);
        }
        if (r.debuggable) {
            total += add(rs, C_DEBUGGABLE, "Is a debug build (debuggable flag set) — unusual for a real released app.", Fix.NONE);
        }
        if (r.cleartextAllowed && internet) {
            total += add(rs, C_CLEARTEXT, "Allows unencrypted (http) network traffic.", Fix.NONE);
        }
        if (r.exportedUnprotected >= 5) {
            total += add(rs, C_EXPORTED, r.exportedUnprotected + " internal components are open to other apps without protection.", Fix.NONE);
        }

        if (!r.isSystem && !r.hasLauncherIcon && !r.accessibilityDeclared && !r.isKeyboard) {
            total += add(rs, C_HIDDEN_ICON, "Has no icon in your app drawer, so it's hard to find and remove. Malware often hides itself this way.", Fix.UNINSTALL);
        }

        // ---------------- Network monitor findings ----------------
        if (!r.netFlags.isEmpty()) {
            java.util.Map<DomainIntel.Kind, List<String>> byKind = new java.util.EnumMap<>(DomainIntel.Kind.class);
            for (java.util.Map.Entry<String, DomainIntel.Kind> e : r.netFlags.entrySet()) {
                List<String> l = byKind.get(e.getValue());
                if (l == null) {
                    l = new ArrayList<>();
                    byKind.put(e.getValue(), l);
                }
                l.add(e.getKey());
            }
            for (java.util.Map.Entry<DomainIntel.Kind, List<String>> e : byKind.entrySet()) {
                List<String> ds = e.getValue();
                String shown = String.join(", ", ds.subList(0, Math.min(3, ds.size()))) + (ds.size() > 3 ? "…" : "");
                total += add(rs, e.getKey().points, "Seen contacting " + shown + ". " + e.getKey().meaning + ".", Fix.UNINSTALL);
            }
            if (smsRead && byKind.containsKey(DomainIntel.Kind.EXFIL)) {
                total += add(rs, C_NET_SMS_EXFIL, "Reads SMS AND talks to a bot/paste/tunnel service: the classic OTP-stealer pattern.", Fix.UNINSTALL);
            }
        }

        if (r.isSystem) {
            total = (int) Math.round(total * SYSTEM_APP_FACTOR);
        }
        r.score = Math.max(0, Math.min(100, total));
        r.band = AppReport.Band.of(r.score);

        rs.sort((a, b) -> b.points - a.points);

        // Every High / Critical app must have at least three plain-language reasons.
        if (r.band.ordinal() >= AppReport.Band.HIGH.ordinal() && rs.size() < 3) {
            rs.add(new Reason(0, "Installed from: " + r.installerLabel + ".", Fix.NONE));
            if (rs.size() < 3) rs.add(new Reason(0, internet ? "Has internet access, so collected data can leave the phone." : "Has no internet permission of its own.", Fix.NONE));
            if (rs.size() < 3) rs.add(new Reason(0, "Targets Android SDK " + r.targetSdk + ".", Fix.NONE));
        }
        if (r.isSystem) {
            rs.add(new Reason(0, "Pre-installed system app: score reduced, since it came with the phone.", Fix.NONE));
        }
        r.reasons.addAll(rs);
    }

    private static String contextMismatch(AppReport r, String hay) {
        boolean utilityByName = UTILITY_WORDS.matcher(hay.replace('.', ' ').replace('_', ' ')).find();
        int cat = r.playCategory;
        boolean mediaCategory = cat == ApplicationInfo.CATEGORY_GAME || cat == ApplicationInfo.CATEGORY_IMAGE
                || cat == ApplicationInfo.CATEGORY_AUDIO || cat == ApplicationInfo.CATEGORY_VIDEO;
        if (!utilityByName && !mediaCategory) return null;

        List<String> odd = new ArrayList<>();
        if (r.has(P + "READ_SMS") || r.has(P + "RECEIVE_SMS") || r.has(P + "SEND_SMS")) odd.add("SMS");
        if (r.has(P + "READ_CONTACTS")) odd.add("contacts");
        if (r.has(P + "READ_CALL_LOG")) odd.add("call log");
        if (r.accessibilityDeclared) odd.add("accessibility");
        if (r.adminDeclared) odd.add("device admin");
        if (r.notifListenerDeclared) odd.add("notification access");
        if (odd.isEmpty()) return null;
        String what = utilityByName ? "a simple utility app" : "a " + categoryName(cat) + " app";
        return "Doesn't add up: " + what + " has no reason to need " + String.join(", ", odd) + ".";
    }

    private static String categoryName(int cat) {
        switch (cat) {
            case ApplicationInfo.CATEGORY_GAME: return "game";
            case ApplicationInfo.CATEGORY_IMAGE: return "photo";
            case ApplicationInfo.CATEGORY_AUDIO: return "music/audio";
            case ApplicationInfo.CATEGORY_VIDEO: return "video";
            default: return "media";
        }
    }

    private static boolean containsAny(String hay, List<String> words) {
        for (String w : words) if (hay.contains(w)) return true;
        return false;
    }

    private static String joinPlain(List<String> items) {
        if (items.size() == 1) return items.get(0);
        return String.join(", ", items.subList(0, items.size() - 1)) + " and " + items.get(items.size() - 1);
    }

    private static int add(List<Reason> rs, int pts, String text, Fix fix) {
        rs.add(new Reason(pts, text, fix));
        return pts;
    }

    /** Special access is capped; reasons are kept but extra points stop counting. */
    private static int cap(List<Reason> rs, int value, int cap) {
        return Math.min(value, cap);
    }

    /** Human-readable name of ApplicationInfo.category, for the detail screen. */
    public static String playCategoryName(int cat) {
        switch (cat) {
            case ApplicationInfo.CATEGORY_GAME: return "Game";
            case ApplicationInfo.CATEGORY_AUDIO: return "Audio";
            case ApplicationInfo.CATEGORY_VIDEO: return "Video";
            case ApplicationInfo.CATEGORY_IMAGE: return "Image";
            case ApplicationInfo.CATEGORY_SOCIAL: return "Social";
            case ApplicationInfo.CATEGORY_NEWS: return "News";
            case ApplicationInfo.CATEGORY_MAPS: return "Maps";
            case ApplicationInfo.CATEGORY_PRODUCTIVITY: return "Productivity";
            case 8: return "Accessibility";
            default: return "Not declared";
        }
    }
}
