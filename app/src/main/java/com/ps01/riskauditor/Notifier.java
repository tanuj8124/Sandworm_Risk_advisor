/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 */
package com.ps01.riskauditor;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

final class Notifier {

    static final String CH_ALERTS = "risk_alerts";
    static final String CH_MONITOR = "monitor";

    private Notifier() {
    }

    static void ensureChannels(Context c) {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        NotificationChannel alerts = new NotificationChannel(CH_ALERTS, "Risky app alerts", NotificationManager.IMPORTANCE_HIGH);
        alerts.setDescription("Shown when a newly installed or updated app looks risky");
        NotificationChannel mon = new NotificationChannel(CH_MONITOR, "Install monitoring", NotificationManager.IMPORTANCE_MIN);
        mon.setDescription("Keeps install monitoring running");
        nm.createNotificationChannel(alerts);
        nm.createNotificationChannel(mon);
    }

    private static Notification.Builder builder(Context c, String channel) {
        return Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(c, channel) : new Notification.Builder(c);
    }

    static Notification monitorNotification(Context c) {
        PendingIntent open = PendingIntent.getActivity(c, 0, new Intent(c, MainActivity.class),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        return builder(c, CH_MONITOR)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle("Watching for new apps and files")
                .setContentText("New installs, updates and downloads are checked on this device")
                .setContentIntent(open)
                .setOngoing(true)
                .build();
    }

    static void networkAlert(Context c, String pkg, String label, String domain, DomainIntel.Kind kind) {
        ensureChannels(c);
        Intent i = (pkg != null && pkg.contains(".") ? DetailActivity.intent(c, pkg) : NetworkActivity.intent(c))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        PendingIntent pi = PendingIntent.getActivity(c, (pkg + domain).hashCode(), i,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        String body = label + " contacted " + domain + ". " + kind.meaning + ".";
        Notification n = builder(c, CH_ALERTS)
                .setSmallIcon(R.drawable.ic_shield)
                .setColor(c.getColor(R.color.band_critical))
                .setContentTitle("Suspicious connection: " + label)
                .setContentText(body)
                .setStyle(new Notification.BigTextStyle().bigText(body))
                .setContentIntent(pi)
                .setAutoCancel(true)
                .setPriority(Notification.PRIORITY_HIGH)
                .build();
        try {
            c.getSystemService(NotificationManager.class).notify((pkg + domain).hashCode(), n);
        } catch (SecurityException ignored) {
        }
    }

    static void fileAlert(Context c, FileAnalyzer.Result r) {
        ensureChannels(c);
        Intent i = FileScanActivity.intent(c).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        PendingIntent pi = PendingIntent.getActivity(c, ("file" + r.location).hashCode(), i,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        String body = r.kind + " in " + FileScanner.where(r) + ". " + r.top();
        Notification n = builder(c, CH_ALERTS)
                .setSmallIcon(R.drawable.ic_shield)
                .setColor(c.getColor(r.severity >= FileAnalyzer.CRITICAL ? R.color.band_critical : R.color.band_high))
                .setContentTitle(FileAnalyzer.SEVERITY_LABEL[r.severity] + " risk file: " + r.name)
                .setContentText(body)
                .setStyle(new Notification.BigTextStyle().bigText(body + " Open the file scanner to delete it."))
                .setContentIntent(pi)
                .setAutoCancel(true)
                .setPriority(Notification.PRIORITY_HIGH)
                .build();
        try {
            c.getSystemService(NotificationManager.class).notify(("file" + r.location).hashCode(), n);
        } catch (SecurityException ignored) {
        }
    }

    static void alert(Context c, AppReport r, boolean isUpdate) {
        ensureChannels(c);
        String title;
        if (r.band.ordinal() >= AppReport.Band.HIGH.ordinal()) {
            title = (isUpdate ? "Updated app is " : "New app is ") + r.band.label.toUpperCase() + " risk: " + r.label;
        } else {
            title = r.label + " update added new permissions";
        }
        if (r.band.ordinal() < AppReport.Band.HIGH.ordinal() && r.mlProbability > MlScanner.MALWARE && r.addedOnUpdate.isEmpty()) {
            title = "AI flagged " + r.label + " as malware-like";
        }
        String body = r.score + "/100 · " + r.mlShort() + " — " + r.topReason();
        Intent i = DetailActivity.intent(c, r.packageName).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        PendingIntent pi = PendingIntent.getActivity(c, r.packageName.hashCode(), i,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification n = builder(c, CH_ALERTS)
                .setSmallIcon(R.drawable.ic_shield)
                .setColor(c.getColor(r.band.colorRes))
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(new Notification.BigTextStyle().bigText(body))
                .setContentIntent(pi)
                .setAutoCancel(true)
                .setPriority(Notification.PRIORITY_HIGH)
                .build();
        try {
            c.getSystemService(NotificationManager.class).notify(r.packageName.hashCode(), n);
        } catch (SecurityException ignored) {
            // POST_NOTIFICATIONS not granted
        }
    }
}
