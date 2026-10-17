/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 * File scanner screen: scan all of phone storage, a picked folder or picked files,
 * watch download folders live, and act on anything flagged (delete / check hash).
 */
package com.ps01.riskauditor;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.Gravity;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FileScanActivity extends Activity {

    private static final int REQ_FILES = 21, REQ_TREE = 22, REQ_STORAGE = 23;
    static final String PREF_WATCH = "watch_files";

    private TextView access, status, summary;
    private Button scanAll, cancel;
    private Switch watch;
    private final ResultAdapter adapter = new ResultAdapter();
    private final ExecutorService exec = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private volatile boolean cancelled = false;
    private volatile boolean busy = false;

    public static Intent intent(Context c) {
        return new Intent(c, FileScanActivity.class);
    }

    static boolean watchEnabled(Context c) {
        return c.getSharedPreferences(MainActivity.PREFS, MODE_PRIVATE).getBoolean(PREF_WATCH, true);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getActionBar() != null) getActionBar().setDisplayHomeAsUpEnabled(true);
        setTitle("File scanner");
        FileScanner.installJudge(this);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.card);
        card.setPadding(dp(14), dp(14), dp(14), dp(14));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(dp(12), dp(12), dp(12), dp(6));

        card.addView(text("Check your files for malware", 17, true, getColor(R.color.primary)));
        card.addView(text("Looks inside each file (not just its name) for Windows programs, app installers, Office macros, "
                + "risky PDFs, scripts, disguised names and password-protected archives. Files are only read on this phone.",
                13, false, getColor(R.color.text_secondary)));
        access = text("", 13, true, getColor(R.color.primary));
        access.setPadding(0, dp(6), 0, 0);
        card.addView(access);

        scanAll = button("Scan all phone storage", v -> scanStorage());
        card.addView(scanAll);
        LinearLayout pickRow = new LinearLayout(this);
        pickRow.addView(button("Pick files…", v -> pickFiles()), new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        pickRow.addView(button("Pick a folder…", v -> pickFolder()), new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        card.addView(pickRow);

        watch = new Switch(this);
        watch.setText("Watch Downloads, WhatsApp & Telegram for new files");
        watch.setChecked(watchEnabled(this));
        watch.setOnCheckedChangeListener((b, checked) -> {
            getSharedPreferences(MainActivity.PREFS, MODE_PRIVATE).edit().putBoolean(PREF_WATCH, checked).apply();
            if (checked) {
                getSharedPreferences(MainActivity.PREFS, MODE_PRIVATE).edit().putBoolean("monitor", true).apply();
                if (!FileScanner.hasAllFiles(this)) requestAllFiles();
            }
            try {
                MonitorService.apply(this, true); // the background monitor hosts the file watcher
            } catch (Exception ignored) {
            }
        });
        card.addView(watch);

        Button eicar = button("Create harmless EICAR test file in Downloads", v -> createEicar());
        eicar.setTextSize(12);
        card.addView(eicar);

        status = text("", 13, false, getColor(R.color.text_secondary));
        card.addView(status);
        cancel = button("Stop scan", v -> cancelled = true);
        cancel.setVisibility(View.GONE);
        card.addView(cancel);
        summary = text("", 14, true, getColor(R.color.primary));
        card.addView(summary);
        root.addView(card, lp);

        ListView list = new ListView(this);
        list.setDivider(null);
        list.setAdapter(adapter);
        list.setOnItemClickListener((parent, view, position, id) -> showResult(adapter.getItem(position)));
        root.addView(list, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(root);
    }

    @Override
    protected void onResume() {
        super.onResume();
        boolean all = FileScanner.hasAllFiles(this);
        access.setText(all ? "✔ Storage access granted" : "Storage access not granted: \"Scan all\" and live watching need it. Picking files works without it.");
        access.setTextColor(all ? getColor(R.color.band_low) : getColor(R.color.band_high));
    }

    @Override
    protected void onDestroy() {
        cancelled = true;
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

    // ------------------------------------------------------------------ actions

    private void scanStorage() {
        if (!FileScanner.hasAllFiles(this)) {
            requestAllFiles();
            return;
        }
        run(p -> FileScanner.scanStorage(p));
    }

    private void pickFiles() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        startActivityForResult(i, REQ_FILES);
    }

    private void pickFolder() {
        startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), REQ_TREE);
    }

    private void requestAllFiles() {
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:" + getPackageName())));
            } catch (Exception e) {
                startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
            }
            Toast.makeText(this, "Allow \"All files access\" for App Risk Auditor, then come back", Toast.LENGTH_LONG).show();
        } else {
            requestPermissions(new String[]{Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE}, REQ_STORAGE);
        }
    }

    private void createEicar() {
        if (!FileScanner.hasAllFiles(this)) {
            requestAllFiles();
            return;
        }
        // Assembled at runtime so this app's own code never contains the full test string.
        byte[] content = FileAnalyzer.eicarTestFile();
        File f = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "eicar_test.com");
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(content);
            Toast.makeText(this, "Created Download/eicar_test.com (harmless test file)", Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, "Could not create test file: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null) return;
        if (requestCode == REQ_FILES) {
            List<Uri> uris = new ArrayList<>();
            ClipData clip = data.getClipData();
            if (clip != null) for (int i = 0; i < clip.getItemCount(); i++) uris.add(clip.getItemAt(i).getUri());
            else if (data.getData() != null) uris.add(data.getData());
            run(p -> {
                List<FileAnalyzer.Result> out = new ArrayList<>();
                int n = 0;
                for (Uri u : uris) {
                    if (p.cancelled()) break;
                    FileAnalyzer.Result r = FileScanner.scanUri(this, u);
                    p.onFile(r.name, ++n);
                    out.add(r); // show picked files even when clean
                }
                return out;
            });
        } else if (requestCode == REQ_TREE && data.getData() != null) {
            Uri tree = data.getData();
            run(p -> FileScanner.scanTree(this, tree, p));
        }
    }

    private interface Job {
        List<FileAnalyzer.Result> run(FileScanner.Progress p);
    }

    private void run(Job job) {
        if (busy) return;
        busy = true;
        cancelled = false;
        cancel.setVisibility(View.VISIBLE);
        scanAll.setEnabled(false);
        summary.setText("");
        status.setText("Starting…");
        final int[] scannedBox = {0};
        FileScanner.Progress p = new FileScanner.Progress() {
            long last = 0;

            @Override
            public void onFile(String name, int scanned) {
                scannedBox[0] = scanned;
                long now = System.currentTimeMillis();
                if (now - last < 150) return;
                last = now;
                ui.post(() -> status.setText("Scanned " + scanned + " files · " + name));
            }

            @Override
            public boolean cancelled() {
                return cancelled;
            }
        };
        exec.execute(() -> {
            List<FileAnalyzer.Result> res;
            try {
                res = job.run(p);
            } catch (Exception e) {
                res = new ArrayList<>();
            }
            Collections.sort(res, (a, b) -> b.severity - a.severity);
            final List<FileAnalyzer.Result> results = res;
            ui.post(() -> {
                busy = false;
                cancel.setVisibility(View.GONE);
                scanAll.setEnabled(true);
                ScanState.lastFiles = results;
                int[] c = new int[4];
                for (FileAnalyzer.Result r : results) c[r.severity]++;
                status.setText((cancelled ? "Stopped. " : "Done. ") + "Checked " + Math.max(scannedBox[0], results.size()) + " files.");
                summary.setText(c[3] + c[2] + c[1] == 0 ? "✔ Nothing risky found."
                        : c[3] + " critical · " + c[2] + " high · " + c[1] + " medium. Tap a file for details.");
                summary.setTextColor(c[3] > 0 ? getColor(R.color.band_critical) : c[2] > 0 ? getColor(R.color.band_high) : getColor(R.color.band_low));
                adapter.set(results);
            });
        });
    }

    // ------------------------------------------------------------------ result detail

    private void showResult(FileAnalyzer.Result r) {
        StringBuilder sb = new StringBuilder();
        sb.append(r.kind).append(" · ").append(FileScanner.where(r));
        if (r.size >= 0) sb.append(" · ").append(human(r.size));
        sb.append("\n\n");
        if (r.findings.isEmpty()) sb.append("Nothing risky found in this file.");
        for (FileAnalyzer.Finding f : r.findings) {
            sb.append("• [").append(FileAnalyzer.SEVERITY_LABEL[f.severity]).append("] ").append(f.text).append("\n\n");
        }
        sb.append("What you can do: if you didn't expect this file, delete it. Never open it on a PC, and never install an APK from outside an app store.");
        AlertDialog.Builder b = new AlertDialog.Builder(this)
                .setTitle(r.name)
                .setMessage(sb.toString())
                .setNegativeButton("Close", null)
                .setNeutralButton("Check hash online", (d, w) -> hashLookup(r));
        if (r.severity >= FileAnalyzer.MEDIUM) b.setPositiveButton("Delete file", (d, w) -> confirmDelete(r));
        b.show();
    }

    private void confirmDelete(FileAnalyzer.Result r) {
        new AlertDialog.Builder(this)
                .setTitle("Delete " + r.name + "?")
                .setMessage("This permanently removes the file from your phone.")
                .setPositiveButton("Delete", (d, w) -> {
                    boolean ok = FileScanner.delete(this, r);
                    Toast.makeText(this, ok ? "Deleted" : "Couldn't delete (no permission for that location)", Toast.LENGTH_LONG).show();
                    if (ok) {
                        List<FileAnalyzer.Result> left = new ArrayList<>(adapter.items);
                        left.remove(r);
                        adapter.set(left);
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void hashLookup(FileAnalyzer.Result r) {
        new AlertDialog.Builder(this)
                .setTitle("Check this file's fingerprint online?")
                .setMessage("The SHA-256 fingerprint is computed on this phone. Only that 64-character code is sent, by opening VirusTotal "
                        + "in your browser. The file itself never leaves the device.")
                .setPositiveButton("Yes, check", (d, w) -> exec.execute(() -> {
                    try {
                        String h = FileScanner.sha256(this, r);
                        ui.post(() -> {
                            try {
                                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://www.virustotal.com/gui/file/" + h)));
                            } catch (Exception e) {
                                Toast.makeText(this, "SHA-256: " + h, Toast.LENGTH_LONG).show();
                            }
                        });
                    } catch (Exception e) {
                        ui.post(() -> Toast.makeText(this, "Couldn't read the file", Toast.LENGTH_SHORT).show());
                    }
                }))
                .setNegativeButton("No", null)
                .show();
    }

    private static String human(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024) + " KB";
        return String.format(java.util.Locale.US, "%.1f MB", bytes / 1048576.0);
    }

    // ------------------------------------------------------------------ list

    private final class ResultAdapter extends BaseAdapter {
        List<FileAnalyzer.Result> items = new ArrayList<>();

        void set(List<FileAnalyzer.Result> items) {
            this.items = items;
            notifyDataSetChanged();
        }

        @Override
        public int getCount() {
            return items.size();
        }

        @Override
        public FileAnalyzer.Result getItem(int position) {
            return items.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            LinearLayout row = new LinearLayout(FileScanActivity.this);
            row.setPadding(dp(12), dp(4), dp(12), dp(4));
            LinearLayout card = new LinearLayout(FileScanActivity.this);
            card.setBackgroundResource(R.drawable.card);
            card.setPadding(dp(12), dp(10), dp(12), dp(10));
            card.setGravity(Gravity.CENTER_VERTICAL);
            row.addView(card, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

            FileAnalyzer.Result r = items.get(position);
            int color = severityColor(r.severity);
            LinearLayout texts = new LinearLayout(FileScanActivity.this);
            texts.setOrientation(LinearLayout.VERTICAL);
            TextView name = text(r.name, 15, true, getColor(R.color.primary));
            name.setSingleLine(true);
            texts.addView(name);
            texts.addView(text(r.kind + " · " + FileScanner.where(r), 11, false, getColor(R.color.text_secondary)));
            TextView top = text(r.top(), 12, false, r.severity >= FileAnalyzer.HIGH ? color : getColor(R.color.text_secondary));
            top.setMaxLines(2);
            texts.addView(top);
            card.addView(texts, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));

            TextView chip = text(FileAnalyzer.SEVERITY_LABEL[r.severity].toUpperCase(), 11, true, Color.WHITE);
            chip.setPadding(dp(8), dp(3), dp(8), dp(3));
            GradientDrawable bg = new GradientDrawable();
            bg.setColor(color);
            bg.setCornerRadius(dp(10));
            chip.setBackground(bg);
            LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            clp.leftMargin = dp(8);
            card.addView(chip, clp);
            return row;
        }
    }

    int severityColor(int sev) {
        switch (sev) {
            case FileAnalyzer.CRITICAL: return getColor(R.color.band_critical);
            case FileAnalyzer.HIGH: return getColor(R.color.band_high);
            case FileAnalyzer.MEDIUM: return getColor(R.color.band_medium);
            default: return getColor(R.color.band_low);
        }
    }

    private Button button(String label, View.OnClickListener l) {
        Button b = new Button(this);
        b.setAllCaps(false);
        b.setText(label);
        b.setOnClickListener(l);
        return b;
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
