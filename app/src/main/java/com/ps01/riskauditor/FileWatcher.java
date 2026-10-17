/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 * Real-time check of newly downloaded / received files, the same idea as Hypatia's
 * realtime scanner (RecursiveFileObserver): watch the folders where files arrive and
 * scan each one as soon as it has been written.
 */
package com.ps01.riskauditor;

import android.content.Context;
import android.os.FileObserver;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class FileWatcher {

    private final Context ctx;
    private final List<FileObserver> observers = new ArrayList<>();
    private ExecutorService exec;

    FileWatcher(Context ctx) {
        this.ctx = ctx.getApplicationContext();
    }

    synchronized boolean running() {
        return !observers.isEmpty();
    }

    @SuppressWarnings("deprecation")
    synchronized void start() {
        if (running()) return;
        FileScanner.installJudge(ctx);
        exec = Executors.newSingleThreadExecutor();
        for (File dir : FileScanner.watchDirs()) {
            FileObserver o = new FileObserver(dir.getAbsolutePath(), FileObserver.CLOSE_WRITE | FileObserver.MOVED_TO) {
                @Override
                public void onEvent(int event, String path) {
                    if (path == null) return;
                    File f = new File(dir, path);
                    if (!f.isFile()) return;
                    ExecutorService e = exec;
                    if (e == null || e.isShutdown()) return;
                    e.execute(() -> {
                        FileAnalyzer.Result r = FileScanner.scanFile(f);
                        if (r.severity >= FileAnalyzer.HIGH) Notifier.fileAlert(ctx, r);
                    });
                }
            };
            o.startWatching();
            observers.add(o);
        }
    }

    synchronized void stop() {
        for (FileObserver o : observers) o.stopWatching();
        observers.clear();
        if (exec != null) exec.shutdownNow();
        exec = null;
    }
}
