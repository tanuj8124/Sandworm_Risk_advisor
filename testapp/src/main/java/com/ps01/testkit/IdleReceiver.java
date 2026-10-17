package com.ps01.testkit;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Declared only so the auditor's AI model sees trojan-like receivers. Does nothing. */
public class IdleReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        // intentionally empty
    }
}
