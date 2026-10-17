/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 * Shareable PDF of the full device scan (stretch 14), built with the framework PdfDocument.
 */
package com.ps01.riskauditor;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.pdf.PdfDocument;
import android.os.Build;

import java.io.IOException;
import java.io.OutputStream;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

final class PdfReport {

    private static final int W = 595, H = 842, M = 40; // A4 in points

    private final Context ctx;
    private final PdfDocument doc = new PdfDocument();
    private PdfDocument.Page page;
    private Canvas canvas;
    private int pageNo = 0;
    private float y;

    private final Paint body = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint bold = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint small = new Paint(Paint.ANTI_ALIAS_FLAG);

    private PdfReport(Context ctx) {
        this.ctx = ctx;
        body.setTextSize(10);
        body.setColor(Color.rgb(31, 42, 68));
        bold.setTextSize(11);
        bold.setTypeface(Typeface.DEFAULT_BOLD);
        bold.setColor(Color.rgb(31, 42, 68));
        small.setTextSize(8.5f);
        small.setColor(Color.rgb(95, 107, 122));
    }

    static void write(Context ctx, List<AppReport> apps, OutputStream out) throws IOException {
        PdfReport p = new PdfReport(ctx);
        try {
            p.render(apps);
            p.doc.writeTo(out);
        } finally {
            p.doc.close();
        }
    }

    private void render(List<AppReport> apps) {
        newPage();
        Paint title = new Paint(bold);
        title.setTextSize(20);
        canvas.drawText("App Risk Audit Report", M, y, title);
        y += 18;
        line(small, "Device: " + Build.MANUFACTURER + " " + Build.MODEL + " · Android " + Build.VERSION.RELEASE
                + " · Generated " + DateFormat.getDateTimeInstance().format(new Date()));
        line(small, "Scanned entirely on-device. No data left the phone to produce this report.");
        y += 8;

        int[] counts = new int[4];
        for (AppReport r : apps) counts[r.band.ordinal()]++;
        line(bold, apps.size() + " apps · Critical " + counts[3] + " · High " + counts[2]
                + " · Medium " + counts[1] + " · Low " + counts[0]);
        y += 6;

        line(bold, "Device-wide access (apps holding each category)");
        for (PermissionCatalog.Category c : PermissionCatalog.Category.values()) {
            int n = 0;
            for (AppReport r : apps) if (r.grantedCategories.contains(c)) n++;
            line(body, "   " + c.title + ": " + n);
        }
        y += 10;

        for (AppReport r : apps) {
            ensure(60);
            Paint bandPaint = new Paint(bold);
            bandPaint.setColor(ctx.getColor(r.band.colorRes));
            canvas.drawText(r.score + "  " + r.band.label.toUpperCase(), W - M - 90, y, bandPaint);
            line(bold, r.label);
            line(small, r.packageName + " · v" + r.versionName + " · installer: " + r.installerLabel
                    + " · target SDK " + r.targetSdk);
            line(small, r.mlShort() + (r.aiDisagrees() ? "  (AI and rules disagree — review manually)" : "")
                    + (r.hasLauncherIcon ? "" : " · HIDDEN ICON"));
            if (!r.netFlags.isEmpty()) wrap(small, "Suspicious servers: " + String.join(", ", r.netFlags.keySet()), 12);
            if (r.band.ordinal() >= AppReport.Band.MEDIUM.ordinal()) {
                int shown = 0;
                for (AppReport.Reason reason : r.reasons) {
                    if (shown++ >= 6) break;
                    wrap(body, (reason.points > 0 ? "+" + reason.points + "  " : "•  ") + reason.text, 12);
                }
            } else if (!r.reasons.isEmpty()) {
                wrap(body, "•  " + r.reasons.get(0).text, 12);
            }
            StringBuilder cats = new StringBuilder();
            for (PermissionCatalog.Category c : r.grantedCategories) {
                if (cats.length() > 0) cats.append(", ");
                cats.append(c.title);
            }
            if (cats.length() > 0) wrap(small, "Holds: " + cats, 12);
            y += 8;
        }
        List<FileAnalyzer.Result> files = ScanState.lastFiles;
        int flaggedFiles = 0;
        for (FileAnalyzer.Result f : files) if (f.flagged()) flaggedFiles++;
        if (flaggedFiles > 0) {
            ensure(40);
            y += 6;
            line(bold, "Flagged files (last file scan): " + flaggedFiles);
            for (FileAnalyzer.Result f : files) {
                if (!f.flagged()) continue;
                ensure(30);
                line(body, FileAnalyzer.SEVERITY_LABEL[f.severity].toUpperCase() + "  " + f.name + "  (" + f.kind + ")");
                wrap(small, FileScanner.where(f) + " · " + f.top(), 12);
            }
        }
        doc.finishPage(page);
    }

    private void newPage() {
        if (page != null) doc.finishPage(page);
        pageNo++;
        page = doc.startPage(new PdfDocument.PageInfo.Builder(W, H, pageNo).create());
        canvas = page.getCanvas();
        canvas.drawText("App Risk Auditor · page " + pageNo, M, H - 20, small);
        y = M + 10;
    }

    private void ensure(float needed) {
        if (y + needed > H - M) newPage();
    }

    private void line(Paint p, String s) {
        ensure(p.getTextSize() + 4);
        canvas.drawText(s, M, y, p);
        y += p.getTextSize() + 4;
    }

    private void wrap(Paint p, String s, int indent) {
        float max = W - 2 * M - indent;
        for (String l : split(p, s, max)) {
            ensure(p.getTextSize() + 3);
            canvas.drawText(l, M + indent, y, p);
            y += p.getTextSize() + 3;
        }
    }

    private static List<String> split(Paint p, String s, float max) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (String word : s.split(" ")) {
            String test = cur.length() == 0 ? word : cur + " " + word;
            if (p.measureText(test) > max && cur.length() > 0) {
                out.add(cur.toString());
                cur = new StringBuilder(word);
            } else {
                cur = new StringBuilder(test);
            }
        }
        if (cur.length() > 0) out.add(cur.toString());
        return out;
    }
}
