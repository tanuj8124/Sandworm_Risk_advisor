/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 * Minimal IPv4/UDP/DNS packet handling for the network monitor. Pure Java (unit-testable).
 */
package com.ps01.riskauditor;

final class DnsPacket {

    /** A parsed DNS query that arrived on the VPN interface. */
    static final class Query {
        byte[] srcIp = new byte[4];
        byte[] dstIp = new byte[4];
        int srcPort, dstPort;
        byte[] dns;          // DNS message (UDP payload)
        String domain;       // first question name, lower-case, no trailing dot
        int qtype;
    }

    private DnsPacket() {
    }

    /** Returns null unless the packet is an IPv4 UDP datagram to port 53 carrying a DNS query. */
    static Query parse(byte[] p, int len) {
        if (len < 28) return null;
        int version = (p[0] >> 4) & 0xF;
        if (version != 4) return null;
        int ihl = (p[0] & 0x0F) * 4;
        int proto = p[9] & 0xFF;
        if (proto != 17 || ihl < 20 || len < ihl + 8) return null;
        int totalLen = u16(p, 2);
        if (totalLen < ihl + 8 || totalLen > len) totalLen = len;
        int udp = ihl;
        Query q = new Query();
        System.arraycopy(p, 12, q.srcIp, 0, 4);
        System.arraycopy(p, 16, q.dstIp, 0, 4);
        q.srcPort = u16(p, udp);
        q.dstPort = u16(p, udp + 2);
        if (q.dstPort != 53) return null;
        int udpLen = u16(p, udp + 4);
        int payloadLen = Math.min(udpLen - 8, totalLen - ihl - 8);
        if (payloadLen < 12) return null;
        q.dns = new byte[payloadLen];
        System.arraycopy(p, udp + 8, q.dns, 0, payloadLen);
        if ((q.dns[2] & 0x80) != 0) return null;        // QR bit set: a response, not a query
        if (u16(q.dns, 4) < 1) return null;              // no questions
        int[] end = new int[1];
        q.domain = readName(q.dns, 12, end);
        if (q.domain == null) return null;
        if (end[0] + 2 <= q.dns.length) q.qtype = u16(q.dns, end[0]);
        return q;
    }

    /** Builds the IPv4/UDP packet that carries a DNS answer back to the asking app. */
    static byte[] buildResponse(Query q, byte[] dns, int dnsLen) {
        int total = 20 + 8 + dnsLen;
        byte[] out = new byte[total];
        out[0] = 0x45;
        put16(out, 2, total);
        out[6] = 0x40;                 // don't fragment
        out[8] = 64;                   // TTL
        out[9] = 17;                   // UDP
        System.arraycopy(q.dstIp, 0, out, 12, 4);   // from the "DNS server"
        System.arraycopy(q.srcIp, 0, out, 16, 4);   // back to the app
        put16(out, 10, ipChecksum(out, 20));
        put16(out, 20, q.dstPort);
        put16(out, 22, q.srcPort);
        put16(out, 24, 8 + dnsLen);
        // UDP checksum 0 = "not computed", allowed for IPv4
        System.arraycopy(dns, 0, out, 28, dnsLen);
        return out;
    }

    /** Reads a (possibly compressed) DNS name. end[0] receives the offset after the name in the original position. */
    static String readName(byte[] m, int off, int[] end) {
        StringBuilder sb = new StringBuilder();
        int pos = off;
        boolean jumped = false;
        int guard = 0;
        while (pos < m.length && guard++ < 128) {
            int l = m[pos] & 0xFF;
            if (l == 0) {
                if (!jumped) end[0] = pos + 1;
                return sb.toString().toLowerCase(java.util.Locale.ROOT);
            }
            if ((l & 0xC0) == 0xC0) {
                if (pos + 1 >= m.length) return null;
                if (!jumped) end[0] = pos + 2;
                pos = ((l & 0x3F) << 8) | (m[pos + 1] & 0xFF);
                jumped = true;
                continue;
            }
            if (pos + 1 + l > m.length) return null;
            if (sb.length() > 0) sb.append('.');
            for (int i = 0; i < l; i++) {
                char c = (char) (m[pos + 1 + i] & 0xFF);
                sb.append(c >= 32 && c < 127 ? c : '?');
            }
            pos += 1 + l;
        }
        return null;
    }

    static int ipChecksum(byte[] b, int len) {
        long sum = 0;
        for (int i = 0; i + 1 < len; i += 2) sum += u16(b, i);
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }

    static int u16(byte[] b, int i) {
        return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
    }

    static void put16(byte[] b, int i, int v) {
        b[i] = (byte) (v >> 8);
        b[i + 1] = (byte) v;
    }
}
