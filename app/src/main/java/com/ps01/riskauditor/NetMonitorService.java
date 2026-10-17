/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 *
 * Network monitor. A local, on-device VPN that captures only DNS: the VPN routes just one
 * fake DNS address (10.111.222.1) and tells Android to use it, so every app's DNS lookups
 * arrive here while all other traffic goes out normally and untouched. Each lookup is
 * attributed to the app that made it (ConnectivityManager.getConnectionOwnerUid, Android 10+),
 * classified by DomainIntel, logged, and forwarded unchanged to the phone's normal DNS server.
 *
 * No root, no certificates, no traffic content is read and nothing is stored off the device.
 * Same approach as open-source DNS66 / personalDNSfilter / RethinkDNS.
 */
package com.ps01.riskauditor;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.system.OsConstants;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class NetMonitorService extends VpnService implements Runnable {

    static final String ACTION_START = "com.ps01.riskauditor.NET_START";
    static final String ACTION_STOP = "com.ps01.riskauditor.NET_STOP";
    static final String VPN_ADDR = "10.111.222.2";
    static final String DNS_ADDR = "10.111.222.1";

    private ParcelFileDescriptor tun;
    private FileOutputStream tunOut;
    private Thread reader;
    private ExecutorService pool;

    private volatile List<InetAddress> upstream = new ArrayList<>();
    private volatile long upstreamTime = 0;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            stopSelf();
            return START_NOT_STICKY;
        }
        startVpn();
        return START_STICKY;
    }

    @Override
    public void onRevoke() {
        // User turned the VPN off in system settings, or another VPN took over
        stopVpn();
        stopSelf();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    private synchronized void startVpn() {
        if (tun != null) return;
        refreshUpstream(true);
        try {
            Builder b = new Builder()
                    .setSession("App Risk Auditor · DNS monitor")
                    .addAddress(VPN_ADDR, 32)
                    .addRoute(DNS_ADDR, 32)       // only DNS goes through us
                    .addDnsServer(DNS_ADDR)
                    .setBlocking(true);
            try {
                b.addDisallowedApplication(getPackageName());
            } catch (PackageManager.NameNotFoundException ignored) {
            }
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
            b.setConfigureIntent(PendingIntent.getActivity(this, 7,
                    new Intent(this, NetworkActivity.class), PendingIntent.FLAG_IMMUTABLE));
            tun = b.establish();
        } catch (Exception e) {
            tun = null;
        }
        if (tun == null) {
            NetLog.running = false;
            NetLog.status = "Could not start (VPN permission not granted?)";
            NetLog.notifyListeners();
            return;
        }
        tunOut = new FileOutputStream(tun.getFileDescriptor());
        pool = Executors.newFixedThreadPool(4);
        reader = new Thread(this, "dns-monitor");
        reader.setDaemon(true);
        reader.start();
        NetLog.markRan(this);
        NetLog.running = true;
        NetLog.status = Build.VERSION.SDK_INT >= 29
                ? "Running · watching DNS lookups of every app"
                : "Running · app names need Android 10+, lookups shown without app";
        NetLog.notifyListeners();
    }

    private synchronized void stopVpn() {
        NetLog.running = false;
        NetLog.status = "Off";
        if (reader != null) reader.interrupt();
        reader = null;
        if (pool != null) pool.shutdownNow();
        pool = null;
        try {
            if (tun != null) tun.close();
        } catch (IOException ignored) {
        }
        tun = null;
        tunOut = null;
        NetLog.notifyListeners();
    }

    // ------------------------------------------------------------------ packet loop

    @Override
    public void run() {
        ParcelFileDescriptor fd = tun;
        if (fd == null) return;
        byte[] buf = new byte[32767];
        // Not closed here: the descriptor belongs to the ParcelFileDescriptor, closed in stopVpn().
        FileInputStream in = new FileInputStream(fd.getFileDescriptor());
        try {
            while (!Thread.currentThread().isInterrupted()) {
                int n = in.read(buf);
                if (n < 0) break;
                if (n == 0) continue;
                final DnsPacket.Query q = DnsPacket.parse(buf, n);
                if (q == null) continue;   // e.g. Private-DNS (TCP 853) probes: dropped, Android falls back to UDP 53
                ExecutorService p = pool;
                if (p != null && !p.isShutdown()) p.execute(() -> handle(q));
            }
        } catch (Exception ignored) {
            // interface closed
        }
    }

    private void handle(DnsPacket.Query q) {
        // 1. Who asked? (must happen while the asking socket is still open)
        int uid = ownerUid(q);
        // 2. Forward unchanged to the real DNS server and pass the answer back
        forward(q);
        // 3. Log + classify
        if (uid == Process.myUid()) return;
        String[] who = describeUid(uid);
        DomainIntel.Kind kind = DomainIntel.classify(q.domain, who[0]);
        NetLog.Event e = new NetLog.Event(System.currentTimeMillis(), uid, who[0], who[1], q.domain, kind);
        if (NetLog.add(this, e) && kind.suspicious()) {
            Notifier.networkAlert(this, who[0], who[1], q.domain, kind);
        }
    }

    private int ownerUid(DnsPacket.Query q) {
        if (Build.VERSION.SDK_INT < 29) return -1;
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            return cm.getConnectionOwnerUid(OsConstants.IPPROTO_UDP,
                    new InetSocketAddress(InetAddress.getByAddress(q.srcIp), q.srcPort),
                    new InetSocketAddress(InetAddress.getByAddress(q.dstIp), q.dstPort));
        } catch (Exception e) {
            return -1;
        }
    }

    /** {packageName, label} for a uid. */
    private String[] describeUid(int uid) {
        if (uid < 0) return new String[]{"unknown", "Unknown app"};
        if (uid == 0) return new String[]{"root", "System (root)"};
        if (uid == 1000) return new String[]{"android", "Android system"};
        PackageManager pm = getPackageManager();
        String[] pkgs = pm.getPackagesForUid(uid);
        if (pkgs == null || pkgs.length == 0) return new String[]{"uid:" + uid, "uid " + uid};
        String pkg = pkgs[0];
        String label = pkg;
        try {
            label = String.valueOf(pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)));
        } catch (Exception ignored) {
        }
        if (pkgs.length > 1) label += " (+" + (pkgs.length - 1) + " shared)";
        return new String[]{pkg, label};
    }

    private void forward(DnsPacket.Query q) {
        refreshUpstream(false);
        for (InetAddress server : upstream) {
            try (DatagramSocket s = new DatagramSocket()) {
                protect(s); // send via the real network, not back into this VPN
                s.setSoTimeout(4000);
                s.send(new DatagramPacket(q.dns, q.dns.length, server, 53));
                byte[] r = new byte[4096];
                DatagramPacket rp = new DatagramPacket(r, r.length);
                s.receive(rp);
                write(DnsPacket.buildResponse(q, r, rp.getLength()));
                return;
            } catch (Exception ignored) {
                // try next server
            }
        }
    }

    private void write(byte[] packet) {
        FileOutputStream out = tunOut;
        if (out == null) return;
        synchronized (this) {
            try {
                out.write(packet);
            } catch (IOException ignored) {
            }
        }
    }

    /** The phone's real DNS servers (from the underlying, non-VPN network). Cached for 30 s. */
    private void refreshUpstream(boolean force) {
        if (!force && System.currentTimeMillis() - upstreamTime < 30_000 && !upstream.isEmpty()) return;
        List<InetAddress> found = new ArrayList<>();
        String warn = null;
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            for (Network n : cm.getAllNetworks()) {
                NetworkCapabilities nc = cm.getNetworkCapabilities(n);
                if (nc == null || !nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                        || !nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                LinkProperties lp = cm.getLinkProperties(n);
                if (lp == null) continue;
                for (InetAddress a : lp.getDnsServers()) {
                    if (!a.getHostAddress().equals(DNS_ADDR) && !found.contains(a)) found.add(a);
                }
                if (Build.VERSION.SDK_INT >= 28 && lp.getPrivateDnsServerName() != null) {
                    warn = "Private DNS is set to \"" + lp.getPrivateDnsServerName() + "\", so Android sends lookups "
                            + "straight there and the monitor can't see them. Set Private DNS to Automatic or Off.";
                }
            }
        } catch (Exception ignored) {
        }
        if (found.isEmpty()) {
            try {
                // Fallback only if the network reports no DNS server at all
                found.add(InetAddress.getByName("1.1.1.1"));
                found.add(InetAddress.getByName("8.8.8.8"));
            } catch (Exception ignored) {
            }
        }
        upstream = found;
        upstreamTime = System.currentTimeMillis();
        NetLog.warning = warn;
    }
}
