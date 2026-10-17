/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 *
 * Install monitoring (requirements 09 and 10). Since Android 8, PACKAGE_ADDED cannot be
 * received by a manifest receiver, so a small foreground service registers for it at runtime.
 * Each new or updated app is rescanned on the device; the user is notified if it scores
 * High/Critical or if an update added sensitive permissions.
 */
package com.ps01.riskauditor;

import android.app.Notification;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ServiceInfo;
import android.net.Uri;
import android.os.Build;
import android.os.IBinder;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MonitorService extends Service {

    private static final int FG_ID = 1;
    private BroadcastReceiver receiver;
    private ExecutorService exec;
    private FileWatcher fileWatcher;

    public static void apply(Context c, boolean on) {
        Intent i = new Intent(c, MonitorService.class);
        if (on) {
            if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i);
            else c.startService(i);
        } else {
            c.stopService(i);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Notifier.ensureChannels(this);
        Notification n = Notifier.monitorNotification(this);
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(FG_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(FG_ID, n);
        }

        exec = Executors.newSingleThreadExecutor();
        receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                handle(intent);
            }
        };
        IntentFilter f = new IntentFilter();
        f.addAction(Intent.ACTION_PACKAGE_ADDED);
        f.addAction(Intent.ACTION_PACKAGE_REPLACED);
        f.addAction(Intent.ACTION_PACKAGE_FULLY_REMOVED);
        f.addDataScheme("package");
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(receiver, f, Context.RECEIVER_EXPORTED);
        } else {
            registerReceiver(receiver, f);
        }
    }

    private void handle(Intent intent) {
        Uri data = intent.getData();
        String action = intent.getAction();
        if (data == null || action == null) return;
        final String pkg = data.getSchemeSpecificPart();
        if (pkg == null || pkg.equals(getPackageName())) return;

        ScanState.dirty = true;
        if (Intent.ACTION_PACKAGE_FULLY_REMOVED.equals(action)) return;
        // An update sends ADDED(replacing=true) and then REPLACED: handle only the REPLACED one.
        if (Intent.ACTION_PACKAGE_ADDED.equals(action) && intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return;
        final boolean isUpdate = Intent.ACTION_PACKAGE_REPLACED.equals(action);

        exec.execute(() -> {
            AppReport r = new AppScanner(this).scanPackage(pkg);
            if (r == null) return;
            boolean risky = r.band.ordinal() >= AppReport.Band.HIGH.ordinal();
            boolean newPerms = isUpdate && !r.addedOnUpdate.isEmpty();
            boolean aiMalware = r.mlProbability > MlScanner.MALWARE;
            if (risky || newPerms || aiMalware) Notifier.alert(this, r, isUpdate);
        });
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        refreshFileWatcher();
        return START_STICKY;
    }

    /** Live file checks run here when the user enabled them and granted storage access. */
    private void refreshFileWatcher() {
        boolean want = FileScanActivity.watchEnabled(this) && FileScanner.hasAllFiles(this);
        if (fileWatcher == null) fileWatcher = new FileWatcher(this);
        if (want) fileWatcher.start();
        else fileWatcher.stop();
    }

    @Override
    public void onDestroy() {
        if (receiver != null) unregisterReceiver(receiver);
        if (fileWatcher != null) fileWatcher.stop();
        if (exec != null) exec.shutdown();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
