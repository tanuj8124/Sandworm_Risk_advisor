/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 *
 * Offline classification of domains seen by the network monitor. Small built-in lists,
 * no lookups: the point is to spot the infrastructure Android malware typically uses to
 * send stolen data out (bot APIs, tunnels, paste sites, free dynamic DNS, random names).
 */
package com.ps01.riskauditor;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

final class DomainIntel {

    enum Kind {
        NORMAL("", 0),
        TRACKER("Advertising / tracking service", 0),
        EXFIL("Messaging-bot / paste / tunnel service often used by malware to send stolen data out", 15),
        DYNAMIC_DNS("Free dynamic-DNS or throwaway hosting, often used for malware servers", 12),
        RANDOM_NAME("Random-looking domain name (malware sometimes generates these)", 8);

        final String meaning;
        final int points;

        Kind(String meaning, int points) {
            this.meaning = meaning;
            this.points = points;
        }

        boolean suspicious() {
            return points > 0;
        }
    }

    // Exfiltration channels. Telegram bot API is the #1 channel for Indian SMS/OTP stealers.
    private static final List<String> EXFIL = Arrays.asList(
            "api.telegram.org", "pastebin.com", "paste.ee", "ghostbin.com", "hastebin.com",
            "transfer.sh", "file.io", "webhook.site", "requestbin.net", "pipedream.net",
            "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net",
            "loca.lt", "localtunnel.me", "portmap.io", "pagekite.me", "anonfiles.com");

    private static final List<String> DYNAMIC_DNS = Arrays.asList(
            "duckdns.org", "ddns.net", "no-ip.org", "no-ip.com", "hopto.org", "zapto.org", "sytes.net",
            "servebeer.com", "serveftp.com", "dynu.net", "dyndns.org", "freeddns.org", "000webhostapp.com",
            "ddnsfree.com", "linkpc.net", "myftp.biz", "publicvm.com");

    private static final List<String> RISKY_TLDS = Arrays.asList(".tk", ".ml", ".ga", ".cf", ".gq");

    private static final List<String> TRACKERS = Arrays.asList(
            "doubleclick.net", "googleadservices.com", "googlesyndication.com", "google-analytics.com",
            "app-measurement.com", "appsflyer.com", "appsflyersdk.com", "adjust.com", "adjust.io", "branch.io",
            "graph.facebook.com", "an.facebook.com", "applovin.com", "applvn.com", "unityads.unity3d.com",
            "ironsrc.mobi", "supersonicads.com", "inmobi.com", "chartboost.com", "vungle.com",
            "mopub.com", "moatads.com", "onesignal.com", "clevertap-prod.com", "mixpanel.com",
            "amplitude.com", "segment.io", "crashlytics.com", "flurry.com", "startappservice.com");

    private DomainIntel() {
    }

    static Kind classify(String domain, String packageName) {
        if (domain == null || domain.isEmpty()) return Kind.NORMAL;
        String d = domain.toLowerCase(Locale.ROOT);
        if (d.endsWith(".")) d = d.substring(0, d.length() - 1);
        String pkg = packageName == null ? "" : packageName.toLowerCase(Locale.ROOT);

        if (matches(d, EXFIL)) {
            // The real Telegram apps talk to telegram, that's expected.
            if (d.endsWith("telegram.org") && (pkg.contains("telegram") || pkg.contains("telegra"))) return Kind.NORMAL;
            return Kind.EXFIL;
        }
        if (matches(d, DYNAMIC_DNS)) return Kind.DYNAMIC_DNS;
        for (String t : RISKY_TLDS) if (d.endsWith(t)) return Kind.DYNAMIC_DNS;
        if (matches(d, TRACKERS)) return Kind.TRACKER;
        if (looksRandom(d)) return Kind.RANDOM_NAME;
        return Kind.NORMAL;
    }

    private static boolean matches(String d, List<String> list) {
        for (String s : list) if (d.equals(s) || d.endsWith("." + s)) return true;
        return false;
    }

    /** Checks the registrable label (e.g. "xkqjzvb8w2lmn" in xkqjzvb8w2lmn.com) for DGA-like randomness. */
    static boolean looksRandom(String d) {
        String[] parts = d.split("\\.");
        if (parts.length < 2) return false;
        String label = parts[parts.length - 2];
        // Skip short labels and two-part public suffixes like co.in / com.au
        if (label.length() <= 3 && parts.length >= 3) label = parts[parts.length - 3];
        if (label.length() < 12) return false;
        int vowels = 0, digits = 0;
        for (char c : label.toCharArray()) {
            if ("aeiou".indexOf(c) >= 0) vowels++;
            if (Character.isDigit(c)) digits++;
        }
        double vowelRatio = vowels / (double) label.length();
        return entropy(label) > 3.5 && (vowelRatio < 0.22 || digits >= 3);
    }

    static double entropy(String s) {
        int[] counts = new int[128];
        int n = 0;
        for (char c : s.toCharArray()) if (c < 128) {
            counts[c]++;
            n++;
        }
        double h = 0;
        for (int c : counts) if (c > 0) {
            double p = c / (double) n;
            h -= p * (Math.log(p) / Math.log(2));
        }
        return h;
    }
}
