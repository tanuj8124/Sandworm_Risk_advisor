/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 * In-memory log of DNS lookups per app, plus a small persisted list of suspicious domains
 * per app so the risk score remembers them after a restart. Stored only on the device.
 */
package com.ps01.riskauditor;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

final class NetLog {

    static final class Event {
        final long time;
        final int uid;
        final String pkg;
        final String label;
        final String domain;
        final DomainIntel.Kind kind;

        Event(long time, int uid, String pkg, String label, String domain, DomainIntel.Kind kind) {
            this.time = time;
            this.uid = uid;
            this.pkg = pkg;
            this.label = label;
            this.domain = domain;
            this.kind = kind;
        }
    }

    static final class DomainStat {
        final String domain;
        final DomainIntel.Kind kind;
        int count;
        long first, last;

        DomainStat(String domain, DomainIntel.Kind kind, long t) {
            this.domain = domain;
            this.kind = kind;
            this.first = t;
            this.last = t;
        }
    }

    private static final String PREFS = "net_flags";
    private static final int MAX_EVENTS = 1500;

    private static final ArrayDeque<Event> events = new ArrayDeque<>();
    private static final Map<String, Map<String, DomainStat>> byPkg = new HashMap<>();
    private static final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    static volatile boolean running = false;
    static volatile String status = "Off";
    static volatile String warning = null;

    private NetLog() {
    }

    /** Records one lookup. Returns true the first time this app is seen contacting a suspicious domain. */
    static boolean add(Context ctx, Event e) {
        boolean firstSuspicious = false;
        synchronized (NetLog.class) {
            events.addFirst(e);
            while (events.size() > MAX_EVENTS) events.removeLast();
            Map<String, DomainStat> m = byPkg.get(e.pkg);
            if (m == null) {
                m = new LinkedHashMap<>();
                byPkg.put(e.pkg, m);
            }
            DomainStat s = m.get(e.domain);
            if (s == null) {
                s = new DomainStat(e.domain, e.kind, e.time);
                m.put(e.domain, s);
                if (e.kind.suspicious()) firstSuspicious = persistFlag(ctx, e.pkg, e.domain, e.kind);
            }
            s.count++;
            s.last = e.time;
        }
        if (firstSuspicious) ScanState.dirty = true;
        notifyListeners();
        return firstSuspicious;
    }

    static synchronized List<Event> recent(boolean onlySuspicious) {
        List<Event> out = new ArrayList<>();
        for (Event e : events) if (!onlySuspicious || e.kind.suspicious()) out.add(e);
        return out;
    }

    static synchronized List<DomainStat> domainsFor(String pkg) {
        Map<String, DomainStat> m = byPkg.get(pkg);
        List<DomainStat> out = m == null ? new ArrayList<>() : new ArrayList<>(m.values());
        Collections.sort(out, (a, b) -> a.kind.points != b.kind.points ? b.kind.points - a.kind.points : b.count - a.count);
        return out;
    }

    static synchronized int totalLookups() {
        return events.size();
    }

    /** Suspicious domains ever seen for this app (persisted), for the risk score. */
    static Map<String, DomainIntel.Kind> flaggedFor(Context ctx, String pkg) {
        Map<String, DomainIntel.Kind> out = new LinkedHashMap<>();
        String v = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(pkg, null);
        if (v == null || v.isEmpty()) return out;
        for (String part : v.split(";")) {
            int eq = part.indexOf('=');
            if (eq <= 0) continue;
            try {
                out.put(part.substring(0, eq), DomainIntel.Kind.valueOf(part.substring(eq + 1)));
            } catch (IllegalArgumentException ignored) {
            }
        }
        return out;
    }

    static boolean everMonitored(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("_ever_ran", false);
    }

    static void markRan(Context ctx) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("_ever_ran", true).apply();
    }

    private static boolean persistFlag(Context ctx, String pkg, String domain, DomainIntel.Kind kind) {
        SharedPreferences p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        Map<String, DomainIntel.Kind> cur = flaggedFor(ctx, pkg);
        if (cur.containsKey(domain)) return false;
        cur.put(domain, kind);
        StringBuilder sb = new StringBuilder();
        Iterator<Map.Entry<String, DomainIntel.Kind>> it = cur.entrySet().iterator();
        int n = 0;
        while (it.hasNext() && n++ < 30) {
            Map.Entry<String, DomainIntel.Kind> en = it.next();
            if (sb.length() > 0) sb.append(';');
            sb.append(en.getKey()).append('=').append(en.getValue().name());
        }
        p.edit().putString(pkg, sb.toString()).apply();
        return true;
    }

    static void clear(Context ctx) {
        synchronized (NetLog.class) {
            events.clear();
            byPkg.clear();
        }
        boolean ran = everMonitored(ctx);
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().putBoolean("_ever_ran", ran).apply();
        ScanState.dirty = true;
        notifyListeners();
    }

    static void addListener(Runnable r) {
        listeners.add(r);
    }

    static void removeListener(Runnable r) {
        listeners.remove(r);
    }

    static void notifyListeners() {
        for (Runnable r : listeners) r.run();
    }
}
