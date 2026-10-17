/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 *
 * Component explorer: every activity, service, broadcast receiver and content provider an
 * app declares, whether other apps can reach it (exported), what protects it (permission),
 * which intents wake it up, and a plain-language flag for the risky ones.
 */
package com.ps01.riskauditor;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ComponentInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.MenuItem;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ComponentsActivity extends Activity {

    private static final String EXTRA_PKG = "pkg";

    /** One declared component, ready to display. */
    static final class Comp {
        String type;          // Activity / Service / Receiver / Provider
        String name;          // full class name
        boolean exported;
        boolean enabled;
        String permission;    // null = unprotected
        String authority;     // providers only
        List<String> actions = new ArrayList<>();
        List<String> flags = new ArrayList<>();
        int severity;         // 0 info, 1 notable, 2 risky
    }

    /** Intent actions that tell us what wakes a component up, in plain words. */
    private static final Map<String, String> ACTION_MEANING = new HashMap<>();

    static {
        ACTION_MEANING.put("android.intent.action.BOOT_COMPLETED", "starts itself when the phone boots");
        ACTION_MEANING.put("android.intent.action.LOCKED_BOOT_COMPLETED", "starts before you even unlock after boot");
        ACTION_MEANING.put("android.intent.action.QUICKBOOT_POWERON", "starts on (OEM) quick boot");
        ACTION_MEANING.put("android.provider.Telephony.SMS_RECEIVED", "is woken up by every incoming SMS");
        ACTION_MEANING.put("android.provider.Telephony.SMS_DELIVER", "is a default-SMS-app receiver");
        ACTION_MEANING.put("android.provider.Telephony.WAP_PUSH_RECEIVED", "is woken by MMS/WAP push");
        ACTION_MEANING.put("android.intent.action.PHONE_STATE", "is told about every call");
        ACTION_MEANING.put("android.intent.action.NEW_OUTGOING_CALL", "sees numbers you dial");
        ACTION_MEANING.put("android.intent.action.USER_PRESENT", "runs every time you unlock the phone");
        ACTION_MEANING.put("android.intent.action.PACKAGE_ADDED", "watches other apps being installed");
        ACTION_MEANING.put("android.intent.action.PACKAGE_REMOVED", "watches other apps being removed");
        ACTION_MEANING.put("android.net.conn.CONNECTIVITY_CHANGE", "wakes up when the network changes");
        ACTION_MEANING.put("android.intent.action.SCREEN_ON", "wakes up when the screen turns on");
        ACTION_MEANING.put("android.accessibilityservice.AccessibilityService", "is an accessibility service (can read the screen)");
        ACTION_MEANING.put("android.service.notification.NotificationListenerService", "is a notification reader");
        ACTION_MEANING.put("android.app.action.DEVICE_ADMIN_ENABLED", "is a device-admin receiver");
        ACTION_MEANING.put("android.view.InputMethod", "is a keyboard (sees what you type)");
        ACTION_MEANING.put("android.net.VpnService", "is a VPN (can see network traffic)");
        ACTION_MEANING.put("android.intent.action.MAIN", "is an entry point");
    }

    private static final List<String> RISKY_ACTIONS = java.util.Arrays.asList(
            "android.provider.Telephony.SMS_RECEIVED", "android.intent.action.NEW_OUTGOING_CALL",
            "android.accessibilityservice.AccessibilityService", "android.service.notification.NotificationListenerService",
            "android.app.action.DEVICE_ADMIN_ENABLED", "android.view.InputMethod", "android.net.VpnService");

    private String pkg;
    private LinearLayout root;
    private List<Comp> comps = new ArrayList<>();
    private boolean onlyExported = false;
    private final ExecutorService exec = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    public static Intent intent(Context c, String pkg) {
        return new Intent(c, ComponentsActivity.class).putExtra(EXTRA_PKG, pkg);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        pkg = getIntent().getStringExtra(EXTRA_PKG);
        if (getActionBar() != null) getActionBar().setDisplayHomeAsUpEnabled(true);
        setTitle("Components");
        ScrollView scroll = new ScrollView(this);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(12), dp(12), dp(12), dp(24));
        scroll.addView(root);
        setContentView(scroll);
        root.addView(text("Reading the app's manifest…", 14, false, getColor(R.color.text_secondary)));

        exec.execute(() -> {
            List<Comp> list = load(this, pkg);
            ui.post(() -> {
                if (isFinishing()) return;
                comps = list;
                render();
            });
        });
    }

    @Override
    protected void onDestroy() {
        exec.shutdown();
        super.onDestroy();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    // ------------------------------------------------------------------ loading

    /** Reads all four component types (one binder call each, to avoid oversized results). */
    static List<Comp> load(Context ctx, String pkg) {
        PackageManager pm = ctx.getPackageManager();
        List<Comp> out = new ArrayList<>();
        String apk = null;
        try {
            apk = pm.getApplicationInfo(pkg, 0).sourceDir;
        } catch (Exception ignored) {
        }
        ManifestReader.Info mi = ManifestReader.read(apk);
        Map<String, List<String>> actionsByName = new HashMap<>();
        for (Map.Entry<String, List<String>> e : mi.componentActions.entrySet()) {
            actionsByName.put(fullName(pkg, e.getKey()), e.getValue());
        }
        int disabled = PackageManager.MATCH_DISABLED_COMPONENTS;

        PackageInfo pi = info(pm, pkg, PackageManager.GET_ACTIVITIES | disabled);
        if (pi != null && pi.activities != null) for (ActivityInfo a : pi.activities) out.add(make(pm, "Activity", a, a.permission, null, actionsByName));
        pi = info(pm, pkg, PackageManager.GET_SERVICES | disabled);
        if (pi != null && pi.services != null) for (ServiceInfo s : pi.services) out.add(make(pm, "Service", s, s.permission, null, actionsByName));
        pi = info(pm, pkg, PackageManager.GET_RECEIVERS | disabled);
        if (pi != null && pi.receivers != null) for (ActivityInfo a : pi.receivers) out.add(make(pm, "Receiver", a, a.permission, null, actionsByName));
        pi = info(pm, pkg, PackageManager.GET_PROVIDERS | disabled);
        if (pi != null && pi.providers != null) for (ProviderInfo p : pi.providers) {
            String perm = p.readPermission != null ? p.readPermission : p.writePermission;
            out.add(make(pm, "Provider", p, perm, p.authority, actionsByName));
        }
        // Risky first, then exported, then by name
        Collections.sort(out, (x, y) -> x.severity != y.severity ? y.severity - x.severity
                : x.exported != y.exported ? (x.exported ? -1 : 1) : x.name.compareTo(y.name));
        return out;
    }

    private static PackageInfo info(PackageManager pm, String pkg, int flags) {
        try {
            return pm.getPackageInfo(pkg, flags);
        } catch (Exception e) {
            return null;
        }
    }

    private static String fullName(String pkg, String n) {
        if (n.startsWith(".")) return pkg + n;
        if (!n.contains(".")) return pkg + "." + n;
        return n;
    }

    private static Comp make(PackageManager pm, String type, ComponentInfo ci, String perm, String authority,
                             Map<String, List<String>> actionsByName) {
        Comp c = new Comp();
        c.type = type;
        c.name = ci.name;
        c.exported = ci.exported;
        c.permission = perm;
        c.authority = authority;
        c.enabled = ci.enabled;
        try {
            int st = pm.getComponentEnabledSetting(new ComponentName(ci.packageName, ci.name));
            if (st == PackageManager.COMPONENT_ENABLED_STATE_DISABLED
                    || st == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER) c.enabled = false;
            if (st == PackageManager.COMPONENT_ENABLED_STATE_ENABLED) c.enabled = true;
        } catch (Exception ignored) {
        }
        List<String> acts = actionsByName.get(ci.name);
        if (acts != null) c.actions.addAll(acts);

        // Plain-language flags
        for (String a : c.actions) {
            String meaning = ACTION_MEANING.get(a);
            if (meaning != null && !"android.intent.action.MAIN".equals(a)) c.flags.add("It " + meaning + ".");
            if (RISKY_ACTIONS.contains(a)) c.severity = Math.max(c.severity, 2);
            else if (meaning != null && !"android.intent.action.MAIN".equals(a)) c.severity = Math.max(c.severity, 1);
        }
        if (c.exported && perm == null && !c.actions.contains("android.intent.action.MAIN")) {
            if ("Provider".equals(type)) {
                c.flags.add("Any app can read or write its data (no permission).");
                c.severity = 2;
            } else {
                c.flags.add("Any app on the phone can start it (no permission).");
                c.severity = Math.max(c.severity, 1);
            }
        }
        if (c.actions.contains("android.intent.action.MAIN")) c.flags.add("Entry point (shows an icon if it's a launcher activity).");
        if (!c.enabled) c.flags.add("Currently disabled.");
        return c;
    }

    // ------------------------------------------------------------------ UI

    private void render() {
        root.removeAllViews();
        String label = pkg;
        try {
            PackageManager pm = getPackageManager();
            label = String.valueOf(pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)));
        } catch (Exception ignored) {
        }
        setTitle("Components · " + label);

        int[] total = new int[4], exported = new int[4];
        int risky = 0;
        String[] types = {"Activity", "Service", "Receiver", "Provider"};
        for (Comp c : comps) {
            int t = java.util.Arrays.asList(types).indexOf(c.type);
            total[t]++;
            if (c.exported) exported[t]++;
            if (c.severity == 2) risky++;
        }

        LinearLayout head = card();
        head.addView(text(comps.size() + " components", 18, true, getColor(R.color.primary)));
        head.addView(text(String.format("Activities %d (%d open) · Services %d (%d open)\nReceivers %d (%d open) · Providers %d (%d open)",
                total[0], exported[0], total[1], exported[1], total[2], exported[2], total[3], exported[3]),
                13, false, getColor(R.color.text_secondary)));
        if (risky > 0) {
            head.addView(text(risky + " component" + (risky == 1 ? " needs" : "s need") + " attention (shown first, in red).",
                    13, true, getColor(R.color.band_critical)));
        }
        head.addView(text("\"Open\" = exported: other apps can start or talk to it.", 12, false, getColor(R.color.text_secondary)));
        Switch sw = new Switch(this);
        sw.setText("Show only open (exported) components");
        sw.setChecked(onlyExported);
        sw.setOnCheckedChangeListener((b, checked) -> {
            onlyExported = checked;
            render();
        });
        head.addView(sw);
        root.addView(head);

        for (String type : types) {
            List<Comp> ofType = new ArrayList<>();
            for (Comp c : comps) if (c.type.equals(type) && (!onlyExported || c.exported)) ofType.add(c);
            if (ofType.isEmpty()) continue;
            LinearLayout sec = card();
            sec.addView(text(plural(type) + " (" + ofType.size() + ")", 16, true, getColor(R.color.primary)));
            for (Comp c : ofType) sec.addView(row(c));
            root.addView(sec);
        }
        if (comps.isEmpty()) {
            LinearLayout c = card();
            c.addView(text("No components could be read for this app.", 14, false, getColor(R.color.primary)));
            root.addView(c);
        }
    }

    private LinearLayout row(Comp c) {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.VERTICAL);
        r.setPadding(0, dp(8), 0, dp(8));
        int color = c.severity == 2 ? getColor(R.color.band_critical)
                : c.severity == 1 ? getColor(R.color.band_high) : getColor(R.color.primary);
        String shortName = c.name.startsWith(pkg) ? c.name.substring(pkg.length()) : c.name;
        TextView n = text(shortName, 14, true, color);
        n.setTypeface(Typeface.create(Typeface.MONOSPACE, Typeface.BOLD));
        r.addView(n);
        StringBuilder meta = new StringBuilder(c.exported ? "OPEN to other apps" : "Private");
        meta.append(" · ").append(c.permission == null ? "no permission" : "protected by " + shortPerm(c.permission));
        if (c.authority != null) meta.append(" · authority ").append(c.authority);
        if (!c.enabled) meta.append(" · disabled");
        r.addView(text(meta.toString(), 12, false, getColor(R.color.text_secondary)));
        for (String f : c.flags) r.addView(text("• " + f, 13, false, color));
        if (!c.actions.isEmpty()) {
            TextView acts = text("Intents: " + String.join(", ", shortActions(c.actions)), 11, false, getColor(R.color.text_secondary));
            acts.setTypeface(Typeface.MONOSPACE);
            r.addView(acts);
        }
        return r;
    }

    private static List<String> shortActions(List<String> actions) {
        List<String> out = new ArrayList<>();
        for (String a : actions) {
            int i = a.lastIndexOf('.');
            out.add(i >= 0 ? a.substring(i + 1) : a);
        }
        return out;
    }

    private static String shortPerm(String p) {
        int i = p.lastIndexOf('.');
        return i >= 0 ? p.substring(i + 1) : p;
    }

    private static String plural(String type) {
        switch (type) {
            case "Activity": return "Activities (screens)";
            case "Service": return "Services (background work)";
            case "Receiver": return "Receivers (react to system events)";
            default: return "Providers (share data)";
        }
    }

    private LinearLayout card() {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setBackgroundResource(R.drawable.card);
        c.setPadding(dp(14), dp(14), dp(14), dp(14));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(10);
        c.setLayoutParams(lp);
        return c;
    }

    private TextView text(String s, int sp, boolean bold, int color) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
