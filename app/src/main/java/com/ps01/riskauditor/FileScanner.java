/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 * Android glue for FileAnalyzer: walks shared storage (with All-files access), user-picked
 * files and folders (Storage Access Framework, no broad permission needed), and deletes files.
 * Everything is read on the device; nothing is uploaded.
 */
package com.ps01.riskauditor;

import android.Manifest;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class FileScanner {

    interface Progress {
        void onFile(String name, int scanned);

        boolean cancelled();
    }

    /** Folders never walked: other apps' private data and thumbnail caches. */
    private static final Set<String> SKIP_DIRS = new HashSet<>(Arrays.asList(".thumbnails", ".Trash", "cache", ".cache"));
    private static final int MAX_DEPTH = 14;

    private FileScanner() {
    }

    /** Connects APK file checks to the on-device AI model. */
    static void installJudge(Context ctx) {
        final Context app = ctx.getApplicationContext();
        FileAnalyzer.apkJudge = (perms, actions) -> MlScanner.get(app).predict(perms, actions).probability;
    }

    static boolean hasAllFiles(Context c) {
        if (Build.VERSION.SDK_INT >= 30) return Environment.isExternalStorageManager();
        return c.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
    }

    static File storageRoot() {
        return Environment.getExternalStorageDirectory();
    }

    /** Folders where downloaded / received files land; watched live when enabled. */
    static List<File> watchDirs() {
        File root = storageRoot();
        String[] rel = {
                Environment.DIRECTORY_DOWNLOADS, Environment.DIRECTORY_DOCUMENTS, "Bluetooth",
                Environment.DIRECTORY_DOWNLOADS + "/Telegram", Environment.DIRECTORY_DOWNLOADS + "/WhatsApp",
                "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents",
                "Android/media/com.whatsapp.w4b/WhatsApp Business/Media/WhatsApp Business Documents",
                "WhatsApp/Media/WhatsApp Documents",
                "Telegram/Telegram Documents", "Android/media/org.telegram.messenger/Telegram/Telegram Documents"};
        List<File> out = new ArrayList<>();
        for (String r : rel) {
            File f = new File(root, r);
            if (f.isDirectory()) out.add(f);
        }
        return out;
    }

    // ------------------------------------------------------------------ java.io.File

    static FileAnalyzer.Result scanFile(File f) {
        return FileAnalyzer.analyze(f.getName(), f.getAbsolutePath(), f.length(), () -> new FileInputStream(f));
    }

    /** Walks all of shared storage (needs All-files access). Returns flagged files only. */
    static List<FileAnalyzer.Result> scanStorage(Progress p) {
        List<FileAnalyzer.Result> out = new ArrayList<>();
        int[] count = {0};
        walk(storageRoot(), 0, out, count, p);
        return out;
    }

    private static void walk(File dir, int depth, List<FileAnalyzer.Result> out, int[] count, Progress p) {
        if (p.cancelled() || depth > MAX_DEPTH) return;
        File[] kids = dir.listFiles();
        if (kids == null) return;
        for (File f : kids) {
            if (p.cancelled()) return;
            if (f.isDirectory()) {
                String rel = f.getAbsolutePath().substring(storageRoot().getAbsolutePath().length());
                if (rel.startsWith("/Android/data") || rel.startsWith("/Android/obb") || SKIP_DIRS.contains(f.getName())) continue;
                walk(f, depth + 1, out, count, p);
            } else {
                count[0]++;
                p.onFile(f.getName(), count[0]);
                FileAnalyzer.Result r = scanFile(f);
                if (r.flagged()) out.add(r);
            }
        }
    }

    // ------------------------------------------------------------------ content:// (picked files / folders)

    static FileAnalyzer.Result scanUri(Context c, Uri uri) {
        ContentResolver cr = c.getContentResolver();
        String name = uri.getLastPathSegment();
        long size = -1;
        try (Cursor cur = cr.query(uri, new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE}, null, null, null)) {
            if (cur != null && cur.moveToFirst()) {
                if (!cur.isNull(0)) name = cur.getString(0);
                if (!cur.isNull(1)) size = cur.getLong(1);
            }
        } catch (Exception ignored) {
        }
        return FileAnalyzer.analyze(name, uri.toString(), size, () -> open(cr, uri));
    }

    /** Walks a folder the user picked with the system folder picker. Returns flagged files only. */
    static List<FileAnalyzer.Result> scanTree(Context c, Uri tree, Progress p) {
        List<FileAnalyzer.Result> out = new ArrayList<>();
        int[] count = {0};
        try {
            walkTree(c.getContentResolver(), tree, DocumentsContract.getTreeDocumentId(tree), 0, out, count, p);
        } catch (Exception ignored) {
        }
        return out;
    }

    private static void walkTree(ContentResolver cr, Uri tree, String docId, int depth,
                                 List<FileAnalyzer.Result> out, int[] count, Progress p) {
        if (p.cancelled() || depth > MAX_DEPTH) return;
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, docId);
        String[] cols = {DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.COLUMN_SIZE};
        List<String[]> dirs = new ArrayList<>();
        try (Cursor cur = cr.query(children, cols, null, null, null)) {
            if (cur == null) return;
            while (cur.moveToNext() && !p.cancelled()) {
                String id = cur.getString(0);
                String name = cur.getString(1);
                String mime = cur.getString(2);
                long size = cur.isNull(3) ? -1 : cur.getLong(3);
                if (DocumentsContract.Document.MIME_TYPE_DIR.equals(mime)) {
                    dirs.add(new String[]{id});
                    continue;
                }
                count[0]++;
                p.onFile(name, count[0]);
                Uri u = DocumentsContract.buildDocumentUriUsingTree(tree, id);
                FileAnalyzer.Result r = FileAnalyzer.analyze(name, u.toString(), size, () -> open(cr, u));
                if (r.flagged()) out.add(r);
            }
        } catch (Exception ignored) {
        }
        for (String[] d : dirs) walkTree(cr, tree, d[0], depth + 1, out, count, p);
    }

    private static InputStream open(ContentResolver cr, Uri u) throws IOException {
        InputStream in = cr.openInputStream(u);
        if (in == null) throw new IOException("cannot open");
        return in;
    }

    // ------------------------------------------------------------------ actions

    static boolean delete(Context c, FileAnalyzer.Result r) {
        try {
            if (r.location != null && r.location.startsWith("content://")) {
                return DocumentsContract.deleteDocument(c.getContentResolver(), Uri.parse(r.location));
            }
            return r.location != null && new File(r.location).delete();
        } catch (Exception e) {
            return false;
        }
    }

    static String sha256(Context c, FileAnalyzer.Result r) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        try (InputStream in = r.location.startsWith("content://")
                ? open(c.getContentResolver(), Uri.parse(r.location)) : new FileInputStream(r.location)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest()) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** Where a result lives, in friendly words. */
    static String where(FileAnalyzer.Result r) {
        if (r.location == null) return "";
        if (r.location.startsWith("content://")) return "Picked file";
        String root = storageRoot().getAbsolutePath();
        String p = r.location.startsWith(root) ? "Phone storage" + r.location.substring(root.length()) : r.location;
        int slash = p.lastIndexOf('/');
        return slash > 0 ? p.substring(0, slash) : p;
    }
}
