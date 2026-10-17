/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 * Remembers each app's sensitive permissions so an update that adds new ones can be flagged
 * (requirement 10, permission diff). Stored only in this app's private SharedPreferences.
 */
package com.ps01.riskauditor;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.TreeSet;

public final class SnapshotStore {

    private static final String PREFS = "perm_snapshots";
    private static final String ADDED = "added_";

    private SnapshotStore() {
    }

    /**
     * Compares the app with its last snapshot. If the app was updated since, records which
     * sensitive permissions were added. Fills r.addedOnUpdate and refreshes the snapshot.
     */
    public static synchronized void diff(Context ctx, AppReport r) {
        SharedPreferences p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        Set<String> now = new TreeSet<>();
        for (String perm : r.declared) if (PermissionCatalog.isSensitive(perm)) now.add(perm);

        String old = p.getString(r.packageName, null);
        SharedPreferences.Editor ed = p.edit();
        if (old != null) {
            int bar = old.indexOf('|');
            long oldTime = Long.parseLong(old.substring(0, bar));
            if (oldTime != r.lastUpdateTime) {
                Set<String> before = new LinkedHashSet<>();
                String list = old.substring(bar + 1);
                if (!list.isEmpty()) before.addAll(Arrays.asList(list.split(",")));
                Set<String> added = new TreeSet<>(now);
                added.removeAll(before);
                if (added.isEmpty()) ed.remove(ADDED + r.packageName);
                else ed.putString(ADDED + r.packageName, TextUtils.join(",", added));
            }
        }
        ed.putString(r.packageName, r.lastUpdateTime + "|" + TextUtils.join(",", now));
        ed.apply();

        String added = p.getString(ADDED + r.packageName, null);
        r.addedOnUpdate.clear();
        if (!TextUtils.isEmpty(added)) r.addedOnUpdate.addAll(Arrays.asList(added.split(",")));
    }

    public static boolean hasSnapshot(Context ctx, String pkg) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).contains(pkg);
    }
}
