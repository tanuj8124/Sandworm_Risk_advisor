/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 *
 * App detail screen. Answers "Why is it flagged?" (Why-flagged panel) and
 * "What can I do about it right now?" (one-tap fixes, app settings, uninstall).
 */
package com.ps01.riskauditor;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.Gravity;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DetailActivity extends Activity {

    private static final String EXTRA_PKG = "pkg";

    private String pkg;
    private AppReport report;
    private LinearLayout root;
    private String sha256;

    private final ExecutorService exec = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    public static Intent intent(Context c, String pkg) {
        return new Intent(c, DetailActivity.class).putExtra(EXTRA_PKG, pkg);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        pkg = getIntent().getStringExtra(EXTRA_PKG);
        if (getActionBar() != null) getActionBar().setDisplayHomeAsUpEnabled(true);
        ScrollView scroll = new ScrollView(this);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(12), dp(12), dp(12), dp(24));
        scroll.addView(root);
        setContentView(scroll);
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Rescan every time we come back (the user may have changed a setting or uninstalled).
        exec.execute(() -> {
            AppReport r = new AppScanner(this).scanPackage(pkg);
            ui.post(() -> {
                if (isFinishing()) return;
                if (r == null) {
                    Toast.makeText(this, "App removed", Toast.LENGTH_SHORT).show();
                    ScanState.dirty = true;
                    finish();
                    return;
                }
                if (report != null && report.score != r.score) ScanState.dirty = true;
                report = r;
                build();
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

    // ------------------------------------------------------------------ UI

    private void build() {
        AppReport r = report;
        setTitle(r.label);
        root.removeAllViews();
        int bandColor = getColor(r.band.colorRes);

        // Header: icon, name, score
        LinearLayout head = card();
        LinearLayout top = new LinearLayout(this);
        top.setGravity(Gravity.CENTER_VERTICAL);
        ImageView icon = new ImageView(this);
        try {
            icon.setImageDrawable(getPackageManager().getApplicationIcon(r.packageName));
        } catch (PackageManager.NameNotFoundException ignored) {
        }
        top.addView(icon, new LinearLayout.LayoutParams(dp(56), dp(56)));
        LinearLayout names = new LinearLayout(this);
        names.setOrientation(LinearLayout.VERTICAL);
        names.setPadding(dp(12), 0, dp(8), 0);
        names.addView(text(r.label, 19, true, getColor(R.color.primary)));
        names.addView(text(r.packageName, 12, false, getColor(R.color.text_secondary)));
        top.addView(names, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        LinearLayout scoreBox = new LinearLayout(this);
        scoreBox.setOrientation(LinearLayout.VERTICAL);
        scoreBox.setGravity(Gravity.CENTER_HORIZONTAL);
        scoreBox.addView(text(String.valueOf(r.score), 30, true, bandColor));
        TextView band = text(r.band.label.toUpperCase(), 12, true, Color.WHITE);
        band.setPadding(dp(8), dp(2), dp(8), dp(2));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(bandColor);
        bg.setCornerRadius(dp(10));
        band.setBackground(bg);
        scoreBox.addView(band);
        TextView aiTag = text(r.mlShort(), 11, true, r.mlProbability > MlScanner.MALWARE ? getColor(R.color.band_critical)
                : r.mlProbability > MlScanner.RISKY ? getColor(R.color.band_high) : getColor(R.color.text_secondary));
        aiTag.setPadding(0, dp(4), 0, 0);
        scoreBox.addView(aiTag);
        top.addView(scoreBox);
        head.addView(top);
        root.addView(head);

        // Why flagged
        LinearLayout why = section("Why flagged");
        if (r.reasons.isEmpty()) {
            why.addView(text("Nothing risky found: no sensitive permissions or special access.", 14, false, getColor(R.color.primary)));
        }
        for (AppReport.Reason reason : r.reasons) {
            LinearLayout row = new LinearLayout(this);
            row.setPadding(0, dp(6), 0, dp(6));
            TextView pts = text(reason.points > 0 ? "+" + reason.points : "•", 13, true,
                    reason.points >= 15 ? getColor(R.color.band_critical)
                            : reason.points >= 8 ? getColor(R.color.band_high) : getColor(R.color.text_secondary));
            pts.setMinWidth(dp(40));
            row.addView(pts);
            row.addView(text(reason.text, 14, false, getColor(R.color.primary)),
                    new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
            why.addView(row);
        }

        // AI model check (shown beside the rule score; rules stay the explanation)
        LinearLayout aiCard = section("AI model check");
        if (r.mlProbability < 0) {
            aiCard.addView(text(r.mlVerdict + ": the model needs at least one known permission or intent to judge this app.",
                    14, false, getColor(R.color.primary)));
        } else {
            int pct = Math.round(r.mlProbability * 100);
            int c = r.mlProbability > MlScanner.MALWARE ? getColor(R.color.band_critical)
                    : r.mlProbability > MlScanner.RISKY ? getColor(R.color.band_high) : getColor(R.color.band_low);
            aiCard.addView(text(r.mlVerdict + " — " + pct + "% malware probability", 16, true, c));
            aiCard.addView(text("Neural network trained on known malware vs. clean apps. It looked at "
                    + r.mlMatched + " of this app's permissions and intent actions. Runs entirely on this phone.",
                    13, false, getColor(R.color.text_secondary)));
            if (r.aiDisagrees()) {
                aiCard.addView(text(r.mlProbability > MlScanner.MALWARE
                        ? "⚠ The AI thinks this looks like malware even though the rule score is " + r.band.label + ". Worth a closer look."
                        : "The AI rates this low, but the rules found serious access. Trust the reasons above.",
                        13, true, getColor(R.color.band_high)));
            }
        }

        // Network (from the network monitor)
        LinearLayout net = section("Network (servers this app looked up)");
        List<NetLog.DomainStat> domains = NetLog.domainsFor(r.packageName);
        if (domains.isEmpty() && r.netFlags.isEmpty()) {
            net.addView(text(NetLog.running
                    ? "No lookups from this app yet. Use the app, then come back."
                    : "Turn on the network monitor to see which servers this app contacts.",
                    13, false, getColor(R.color.text_secondary)));
        }
        for (java.util.Map.Entry<String, DomainIntel.Kind> f : r.netFlags.entrySet()) {
            boolean live = false;
            for (NetLog.DomainStat d : domains) if (d.domain.equals(f.getKey())) live = true;
            if (!live) net.addView(text("⚠ " + f.getKey() + " — " + f.getValue().meaning, 13, true, getColor(R.color.band_critical)));
        }
        int shownDomains = 0;
        for (NetLog.DomainStat d : domains) {
            if (shownDomains++ >= 25) {
                net.addView(text("… and " + (domains.size() - 25) + " more", 12, false, getColor(R.color.text_secondary)));
                break;
            }
            int col = d.kind.suspicious() ? getColor(R.color.band_critical)
                    : d.kind == DomainIntel.Kind.TRACKER ? getColor(R.color.band_medium) : getColor(R.color.primary);
            TextView dt = text((d.kind.suspicious() ? "⚠ " : "") + d.domain + "  ×" + d.count, 13, d.kind.suspicious(), col);
            dt.setTypeface(d.kind.suspicious() ? Typeface.create(Typeface.MONOSPACE, Typeface.BOLD) : Typeface.MONOSPACE);
            net.addView(dt);
            if (d.kind != DomainIntel.Kind.NORMAL) net.addView(text("    " + d.kind.meaning, 11, false, col));
        }
        Button openNet = new Button(this);
        openNet.setAllCaps(false);
        openNet.setText(NetLog.running ? "Open network monitor (running)" : "Open network monitor");
        openNet.setOnClickListener(v -> startActivity(NetworkActivity.intent(this)));
        net.addView(openNet);

        // What can I do now
        LinearLayout act = section("What you can do now");
        Set<AppReport.Fix> fixes = new LinkedHashSet<>();
        for (AppReport.Reason reason : r.reasons) {
            if (reason.fix != AppReport.Fix.NONE && reason.fix != AppReport.Fix.UNINSTALL) fixes.add(reason.fix);
        }
        for (AppReport.Fix f : fixes) {
            Button b = new Button(this);
            b.setText(fixLabel(f));
            b.setAllCaps(false);
            b.setOnClickListener(v -> applyFix(f));
            act.addView(b);
        }
        Button settings = new Button(this);
        settings.setText("Open app settings (permissions)");
        settings.setAllCaps(false);
        settings.setOnClickListener(v -> applyFix(AppReport.Fix.APP_SETTINGS));
        act.addView(settings);
        Button uninstall = new Button(this);
        uninstall.setText("Uninstall " + r.label);
        uninstall.setAllCaps(false);
        uninstall.setTextColor(getColor(R.color.band_critical));
        uninstall.setOnClickListener(v -> uninstall());
        act.addView(uninstall);
        if (r.isSystem) {
            act.addView(text("System apps usually can't be uninstalled — you can disable them in app settings instead.",
                    12, false, getColor(R.color.text_secondary)));
        }

        // Permissions by category
        LinearLayout permsCard = section("Permissions by category");
        permsCard.addView(text("✔ = granted   ○ = declared only", 12, false, getColor(R.color.text_secondary)));
        for (PermissionCatalog.Category c : PermissionCatalog.Category.values()) {
            List<AppReport.Perm> inCat = new ArrayList<>();
            for (AppReport.Perm p : r.perms) if (p.category == c) inCat.add(p);
            if (inCat.isEmpty()) continue;
            Integer pts = r.categoryPoints.get(c);
            TextView ch = text(c.title + (pts != null && pts > 0 ? "  (+" + pts + ")" : ""), 15, true, getColor(R.color.primary));
            ch.setPadding(0, dp(10), 0, dp(2));
            permsCard.addView(ch);
            for (AppReport.Perm p : inCat) permsCard.addView(permLine(p));
        }
        List<AppReport.Perm> other = new ArrayList<>();
        for (AppReport.Perm p : r.perms) if (p.category == null) other.add(p);
        if (!other.isEmpty()) {
            TextView oh = text("Other permissions (" + other.size() + ")", 15, true, getColor(R.color.primary));
            oh.setPadding(0, dp(10), 0, dp(2));
            permsCard.addView(oh);
            for (AppReport.Perm p : other) permsCard.addView(permLine(p));
        }
        if (r.perms.isEmpty()) permsCard.addView(text("This app requests no permissions.", 14, false, getColor(R.color.primary)));

        // Component explorer
        Button comps = new Button(this);
        comps.setAllCaps(false);
        comps.setText("Show all components (activities, services, receivers, providers)");
        comps.setOnClickListener(v -> startActivity(ComponentsActivity.intent(this, r.packageName)));
        permsCard.addView(comps);

        // App info
        LinearLayout info = section("App info");
        DateFormat df = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT);
        info.addView(kv("Version", r.versionName + " (" + r.versionCode + ")"));
        info.addView(kv("Installed", df.format(new Date(r.firstInstallTime))));
        info.addView(kv("Last updated", df.format(new Date(r.lastUpdateTime))));
        info.addView(kv("Installed by", r.installerLabel + (r.sideloaded ? "  (not an app store)" : "")));
        info.addView(kv("Target SDK", String.valueOf(r.targetSdk)));
        info.addView(kv("Play category", RiskEngine.playCategoryName(r.playCategory)));
        info.addView(kv("System app", r.isSystem ? "Yes" : "No"));
        info.addView(kv("Debuggable", r.debuggable ? "Yes" : "No"));
        info.addView(kv("Cleartext traffic", r.cleartextAllowed ? "Allowed" : "Not allowed"));
        info.addView(kv("Open components", String.valueOf(r.exportedUnprotected)));
        info.addView(kv("App icon", r.hasLauncherIcon ? "Visible in app drawer" : "HIDDEN (no launcher icon)"));

        // Hash lookup (stretch 11)
        LinearLayout hash = section("APK fingerprint (SHA-256)");
        TextView hashText = text(sha256 == null ? "Not computed yet. Hashing happens on this device." : sha256,
                12, false, getColor(R.color.text_secondary));
        hashText.setTypeface(Typeface.MONOSPACE);
        hashText.setTextIsSelectable(true);
        hash.addView(hashText);
        Button compute = new Button(this);
        compute.setAllCaps(false);
        compute.setText(sha256 == null ? "Compute SHA-256" : "Copy hash");
        compute.setOnClickListener(v -> {
            if (sha256 != null) {
                copy(sha256);
                return;
            }
            compute.setEnabled(false);
            hashText.setText("Hashing…");
            exec.execute(() -> {
                String h;
                try {
                    h = AppScanner.sha256(r.apkPath);
                } catch (Exception e) {
                    h = null;
                }
                final String result = h;
                ui.post(() -> {
                    sha256 = result;
                    if (result == null) {
                        hashText.setText("Could not read the APK file.");
                        compute.setEnabled(true);
                    } else {
                        build();
                    }
                });
            });
        });
        hash.addView(compute);
        if (sha256 != null) {
            Button lookup = new Button(this);
            lookup.setAllCaps(false);
            lookup.setText("Check hash online (optional)");
            lookup.setOnClickListener(v -> confirmLookup());
            hash.addView(lookup);
        }
    }

    private View permLine(AppReport.Perm p) {
        String mark = p.granted ? "✔" : "○";
        TextView t = text(mark + "  " + p.shortName() + "  ·  " + p.protection, 13, false,
                p.granted ? getColor(R.color.primary) : getColor(R.color.text_secondary));
        t.setPadding(dp(8), dp(2), 0, dp(2));
        PermissionCatalog.Entry e = PermissionCatalog.get(p.name);
        if (e != null) t.append("\n     " + e.plain);
        return t;
    }

    // ------------------------------------------------------------------ actions

    private String fixLabel(AppReport.Fix f) {
        switch (f) {
            case ACCESSIBILITY: return "Turn off its accessibility access";
            case DEVICE_ADMIN: return "Remove device-admin rights";
            case NOTIFICATION_LISTENER: return "Turn off notification access";
            case OVERLAY: return "Stop it drawing over other apps";
            case UNKNOWN_SOURCES: return "Stop it installing other apps";
            case USAGE_ACCESS: return "Remove usage access";
            case ALL_FILES: return "Remove all-files access";
            case APP_SETTINGS: return "Review / revoke its permissions";
            default: return "Open settings";
        }
    }

    private void applyFix(AppReport.Fix f) {
        Uri pkgUri = Uri.parse("package:" + pkg);
        Intent i;
        switch (f) {
            case ACCESSIBILITY:
                i = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
                break;
            case DEVICE_ADMIN:
                i = new Intent(Settings.ACTION_SECURITY_SETTINGS);
                toast("Open \"Device admin apps\" and switch " + report.label + " off");
                break;
            case NOTIFICATION_LISTENER:
                i = new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS);
                break;
            case OVERLAY:
                i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, pkgUri);
                break;
            case UNKNOWN_SOURCES:
                i = Build.VERSION.SDK_INT >= 26 ? new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, pkgUri)
                        : new Intent(Settings.ACTION_SECURITY_SETTINGS);
                break;
            case USAGE_ACCESS:
                i = new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS);
                break;
            case ALL_FILES:
                i = Build.VERSION.SDK_INT >= 30 ? new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, pkgUri)
                        : new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkgUri);
                break;
            case UNINSTALL:
                uninstall();
                return;
            default:
                i = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkgUri);
        }
        start(i);
    }

    private void start(Intent i) {
        try {
            startActivity(i);
        } catch (Exception e) {
            // Some OEM builds lack a specific screen: fall back to the app's info page.
            try {
                startActivity(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + pkg)));
            } catch (Exception e2) {
                toast("Could not open settings");
            }
        }
    }

    private void uninstall() {
        if (report.adminActive) {
            new AlertDialog.Builder(this)
                    .setTitle("Remove device-admin first")
                    .setMessage(report.label + " is a device admin, which blocks uninstalling. Turn it off under "
                            + "Security → Device admin apps, then come back and tap Uninstall again.")
                    .setPositiveButton("Open security settings", (d, w) -> start(new Intent(Settings.ACTION_SECURITY_SETTINGS)))
                    .setNegativeButton("Cancel", null)
                    .show();
            return;
        }
        ScanState.dirty = true;
        start(new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + pkg)));
    }

    private void confirmLookup() {
        new AlertDialog.Builder(this)
                .setTitle("Check this hash online?")
                .setMessage("Only the 64-character SHA-256 fingerprint will be sent, by opening VirusTotal in your browser. "
                        + "The app itself and none of your data leave the device. Continue?")
                .setPositiveButton("Yes, check hash", (d, w) -> start(new Intent(Intent.ACTION_VIEW,
                        Uri.parse("https://www.virustotal.com/gui/file/" + sha256))))
                .setNegativeButton("No", null)
                .show();
    }

    private void copy(String s) {
        ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("sha256", s));
        toast("Hash copied");
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
    }

    // ------------------------------------------------------------------ view helpers

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

    private LinearLayout section(String title) {
        LinearLayout c = card();
        TextView t = text(title, 17, true, getColor(R.color.primary));
        t.setPadding(0, 0, 0, dp(6));
        c.addView(t);
        root.addView(c);
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

    private View kv(String k, String v) {
        LinearLayout row = new LinearLayout(this);
        row.setPadding(0, dp(3), 0, dp(3));
        TextView kt = text(k, 13, false, getColor(R.color.text_secondary));
        row.addView(kt, new LinearLayout.LayoutParams(dp(120), LinearLayout.LayoutParams.WRAP_CONTENT));
        row.addView(text(v, 13, false, getColor(R.color.primary)),
                new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        return row;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
