/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 *
 * Home screen. Answers "Which of my apps can do the most harm?":
 * apps sorted by risk score, band filter chips, and a device-wide summary
 * of how many apps hold each kind of access.
 */
package com.ps01.riskauditor;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {

    static final String PREFS = "settings";
    private static final int REQ_PDF = 1;
    private static final int REQ_NOTIF = 2;

    private ListView list;
    private AppListAdapter adapter;
    private TextView title, sub;
    private LinearLayout bandRow, categoryCard;
    private ProgressBar progress;
    private Switch systemSwitch, monitorSwitch;

    private List<AppReport> all = new ArrayList<>();
    private AppReport.Band filter = null;
    private boolean scanning = false;

    private final ExecutorService exec = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    static boolean monitorEnabled(Context c) {
        return c.getSharedPreferences(PREFS, MODE_PRIVATE).getBoolean("monitor", true);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        list = findViewById(R.id.list);
        progress = findViewById(R.id.progress);

        View header = getLayoutInflater().inflate(R.layout.header_main, list, false);
        list.addHeaderView(header, null, false);
        title = header.findViewById(R.id.summary_title);
        sub = header.findViewById(R.id.summary_sub);
        bandRow = header.findViewById(R.id.band_row);
        categoryCard = header.findViewById(R.id.category_card);
        systemSwitch = header.findViewById(R.id.switch_system);
        monitorSwitch = header.findViewById(R.id.switch_monitor);
        Button rescan = header.findViewById(R.id.btn_rescan);
        Button pdf = header.findViewById(R.id.btn_pdf);

        adapter = new AppListAdapter(this);
        list.setAdapter(adapter);
        list.setOnItemClickListener((parent, view, position, id) -> {
            Object o = parent.getItemAtPosition(position);
            if (o instanceof AppReport) {
                startActivity(DetailActivity.intent(this, ((AppReport) o).packageName));
            }
        });

        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        systemSwitch.setChecked(prefs.getBoolean("system", false));
        systemSwitch.setOnCheckedChangeListener((b, checked) -> {
            prefs.edit().putBoolean("system", checked).apply();
            scan();
        });
        monitorSwitch.setChecked(prefs.getBoolean("monitor", true));
        monitorSwitch.setOnCheckedChangeListener((b, checked) -> {
            prefs.edit().putBoolean("monitor", checked).apply();
            startMonitor(checked);
        });

        rescan.setOnClickListener(v -> scan());
        header.findViewById(R.id.btn_network).setOnClickListener(v -> startActivity(NetworkActivity.intent(this)));
        header.findViewById(R.id.btn_files).setOnClickListener(v -> startActivity(FileScanActivity.intent(this)));
        pdf.setOnClickListener(v -> exportPdf());

        requestNotificationPermission();
        startMonitor(monitorSwitch.isChecked());
        scan();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (ScanState.dirty) scan();
    }

    @Override
    protected void onDestroy() {
        exec.shutdown();
        super.onDestroy();
    }

    private void startMonitor(boolean on) {
        try {
            MonitorService.apply(this, on);
        } catch (Exception e) {
            Toast.makeText(this, "Could not start install monitoring: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIF);
        }
    }

    // ------------------------------------------------------------------ scanning

    private void scan() {
        if (scanning) return;
        scanning = true;
        ScanState.dirty = false;
        progress.setVisibility(View.VISIBLE);
        title.setText(R.string.scanning);
        final boolean includeSystem = systemSwitch.isChecked();
        exec.execute(() -> {
            List<AppReport> res;
            try {
                res = new AppScanner(this).scanAll(includeSystem);
            } catch (Exception e) {
                res = new ArrayList<>();
            }
            final List<AppReport> results = res;
            ui.post(() -> {
                scanning = false;
                if (isFinishing()) return;
                all = results;
                ScanState.last = results;
                progress.setVisibility(View.GONE);
                render();
            });
        });
    }

    // ------------------------------------------------------------------ rendering

    private void render() {
        Map<AppReport.Band, Integer> counts = new EnumMap<>(AppReport.Band.class);
        for (AppReport.Band b : AppReport.Band.values()) counts.put(b, 0);
        Map<PermissionCatalog.Category, Integer> catCounts = new EnumMap<>(PermissionCatalog.Category.class);
        for (PermissionCatalog.Category c : PermissionCatalog.Category.values()) catCounts.put(c, 0);
        for (AppReport r : all) {
            counts.put(r.band, counts.get(r.band) + 1);
            for (PermissionCatalog.Category c : r.grantedCategories) catCounts.put(c, catCounts.get(c) + 1);
        }

        int attention = counts.get(AppReport.Band.HIGH) + counts.get(AppReport.Band.CRITICAL);
        int aiFlagged = 0, disagree = 0;
        for (AppReport r : all) {
            if (r.mlFlagged()) aiFlagged++;
            if (r.aiDisagrees()) disagree++;
        }
        title.setText(all.size() + " apps scanned");
        String aiLine = "AI model flagged " + aiFlagged + (aiFlagged == 1 ? " app" : " apps")
                + (disagree > 0 ? " · AI and rules disagree on " + disagree : "") + ". ";
        sub.setText((attention == 0
                ? "No High or Critical apps found. "
                : attention + (attention == 1 ? " app needs" : " apps need") + " your attention. ")
                + aiLine + getString(R.string.tap_band_hint));

        // Band chips (Critical first)
        bandRow.removeAllViews();
        AppReport.Band[] order = {AppReport.Band.CRITICAL, AppReport.Band.HIGH, AppReport.Band.MEDIUM, AppReport.Band.LOW};
        for (AppReport.Band b : order) {
            TextView chip = new TextView(this);
            boolean selected = filter == b;
            int color = getColor(b.colorRes);
            GradientDrawable bg = new GradientDrawable();
            bg.setCornerRadius(dp(16));
            bg.setStroke(dp(1), color);
            bg.setColor(selected ? color : Color.WHITE);
            chip.setBackground(bg);
            chip.setTextColor(selected ? Color.WHITE : color);
            chip.setTypeface(Typeface.DEFAULT_BOLD);
            chip.setGravity(Gravity.CENTER);
            chip.setTextSize(12);
            chip.setPadding(dp(4), dp(6), dp(4), dp(6));
            chip.setText(counts.get(b) + "\n" + b.label);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1);
            lp.setMargins(dp(3), 0, dp(3), 0);
            chip.setOnClickListener(v -> {
                filter = (filter == b) ? null : b;
                render();
            });
            bandRow.addView(chip, lp);
        }

        // Device-wide category summary
        categoryCard.removeAllViews();
        TextView h = new TextView(this);
        h.setText("Device-wide access (apps holding it)");
        h.setTextSize(15);
        h.setTypeface(Typeface.DEFAULT_BOLD);
        h.setTextColor(getColor(R.color.primary));
        categoryCard.addView(h);
        for (PermissionCatalog.Category c : PermissionCatalog.Category.values()) {
            LinearLayout row = new LinearLayout(this);
            row.setPadding(0, dp(5), 0, 0);
            TextView name = new TextView(this);
            name.setText(String.format(Locale.US, "%02d  %s", c.ordinal() + 1, c.title));
            name.setTextColor(getColor(R.color.primary));
            TextView n = new TextView(this);
            int count = catCounts.get(c);
            n.setText(count + (count == 1 ? " app" : " apps"));
            n.setTypeface(Typeface.DEFAULT_BOLD);
            if (c == PermissionCatalog.Category.SPECIAL && count > 0) n.setTextColor(getColor(R.color.band_critical));
            row.addView(name, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
            row.addView(n);
            categoryCard.addView(row);
        }

        List<AppReport> shown = new ArrayList<>();
        for (AppReport r : all) if (filter == null || r.band == filter) shown.add(r);
        adapter.setItems(shown);
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    // ------------------------------------------------------------------ PDF export (stretch 14)

    private void exportPdf() {
        if (all.isEmpty()) {
            Toast.makeText(this, "Run a scan first", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("application/pdf");
        String stamp = new SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(new Date());
        i.putExtra(Intent.EXTRA_TITLE, "app-risk-report-" + stamp + ".pdf");
        startActivityForResult(i, REQ_PDF);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_PDF || resultCode != RESULT_OK || data == null || data.getData() == null) return;
        final Uri uri = data.getData();
        final List<AppReport> snapshot = new ArrayList<>(all);
        exec.execute(() -> {
            String msg;
            try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                PdfReport.write(this, snapshot, out);
                msg = "PDF report saved";
            } catch (Exception e) {
                msg = "Could not save PDF: " + e.getMessage();
            }
            final String m = msg;
            ui.post(() -> Toast.makeText(this, m, Toast.LENGTH_LONG).show());
        });
    }
}
