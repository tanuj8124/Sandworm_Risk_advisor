/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 * Restarts install monitoring after a reboot or after this app is updated
 * (same idea as Hypatia's EventReceiver).
 */
package com.ps01.riskauditor;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String a = intent.getAction();
        if (Intent.ACTION_BOOT_COMPLETED.equals(a) || Intent.ACTION_MY_PACKAGE_REPLACED.equals(a)) {
            if (MainActivity.monitorEnabled(context)) {
                try {
                    MonitorService.apply(context, true);
                } catch (Exception ignored) {
                    // Some OEMs block background starts; the next app launch starts it again.
                }
            }
        }
    }
}
