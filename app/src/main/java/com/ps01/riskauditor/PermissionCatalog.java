/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 * Maps Android permissions to the nine PS-01 categories, with a risk weight
 * and a plain-language description of what the permission lets an app do.
 */
package com.ps01.riskauditor;

import java.util.HashMap;
import java.util.Map;

public final class PermissionCatalog {

    public enum Category {
        SPECIAL("Special access",
                "Screen reading, fake login screens, blocking uninstall, reading OTPs from notifications, installing more apps", 45),
        SMS("SMS", "OTP theft and premium-SMS fraud", 25),
        CONTACTS("Contacts & call logs", "Harvesting your contacts for scams and extortion", 15),
        CAMERA_MIC("Camera & microphone", "Covert recording", 12),
        LOCATION("Location", "Tracking and stalking", 12),
        PHONE("Phone & identity", "Device fingerprinting and call fraud", 10),
        STORAGE("Storage & media", "Photo and document theft", 10),
        BACKGROUND("Background & persistence", "Survives reboots and keeps running unseen", 8),
        NETWORK("Network", "The channel to send data out (low risk alone)", 2);

        public final String title;
        public final String why;
        /** Maximum points this category can add to the score. */
        public final int cap;

        Category(String title, String why, int cap) {
            this.title = title;
            this.why = why;
            this.cap = cap;
        }
    }

    public static final class Entry {
        public final Category category;
        /** Points when granted. Declared-but-not-granted counts DECLARED_FACTOR of this. */
        public final int points;
        public final String plain;

        Entry(Category category, int points, String plain) {
            this.category = category;
            this.points = points;
            this.plain = plain;
        }
    }

    public static final double DECLARED_FACTOR = 0.4;

    private static final Map<String, Entry> MAP = new HashMap<>();

    private static void add(String perm, Category c, int points, String plain) {
        MAP.put(perm.startsWith("android.") ? perm : "android.permission." + perm, new Entry(c, points, plain));
    }

    static {
        // 01 Special access — scored from live system state in RiskEngine, points here are 0.
        add("SYSTEM_ALERT_WINDOW", Category.SPECIAL, 0, "draw over other apps (fake login screens)");
        add("BIND_ACCESSIBILITY_SERVICE", Category.SPECIAL, 0, "read your screen and tap for you");
        add("BIND_DEVICE_ADMIN", Category.SPECIAL, 0, "act as device admin (can block uninstall, wipe or lock the phone)");
        add("BIND_NOTIFICATION_LISTENER_SERVICE", Category.SPECIAL, 0, "read all your notifications (including OTPs)");
        add("REQUEST_INSTALL_PACKAGES", Category.SPECIAL, 0, "install other apps");
        add("PACKAGE_USAGE_STATS", Category.SPECIAL, 0, "see which apps you use and when");

        // 02 SMS
        add("READ_SMS", Category.SMS, 15, "read your text messages");
        add("RECEIVE_SMS", Category.SMS, 12, "receive incoming SMS (OTP codes)");
        add("SEND_SMS", Category.SMS, 12, "send SMS (can cost you money)");
        add("RECEIVE_MMS", Category.SMS, 6, "receive MMS");
        add("RECEIVE_WAP_PUSH", Category.SMS, 6, "receive WAP push messages");

        // 03 Contacts & call logs
        add("READ_CONTACTS", Category.CONTACTS, 8, "read your contacts");
        add("WRITE_CONTACTS", Category.CONTACTS, 4, "change your contacts");
        add("GET_ACCOUNTS", Category.CONTACTS, 3, "list accounts on the device");
        add("READ_CALL_LOG", Category.CONTACTS, 12, "read your call history");
        add("WRITE_CALL_LOG", Category.CONTACTS, 5, "change your call history");
        add("PROCESS_OUTGOING_CALLS", Category.CONTACTS, 8, "see and redirect outgoing calls");

        // 04 Camera & microphone
        add("CAMERA", Category.CAMERA_MIC, 8, "use the camera");
        add("RECORD_AUDIO", Category.CAMERA_MIC, 8, "record audio with the microphone");

        // 05 Location
        add("ACCESS_FINE_LOCATION", Category.LOCATION, 6, "know your precise location");
        add("ACCESS_COARSE_LOCATION", Category.LOCATION, 3, "know your approximate location");
        add("ACCESS_BACKGROUND_LOCATION", Category.LOCATION, 10, "track your location in the background");

        // 06 Phone & identity
        add("READ_PHONE_STATE", Category.PHONE, 4, "read phone status and identity");
        add("READ_PHONE_NUMBERS", Category.PHONE, 5, "read your phone number");
        add("CALL_PHONE", Category.PHONE, 6, "make phone calls without you dialling");
        add("ANSWER_PHONE_CALLS", Category.PHONE, 5, "answer phone calls");
        add("READ_PRIVILEGED_PHONE_STATE", Category.PHONE, 5, "read device identifiers");

        // 07 Storage & media
        add("READ_MEDIA_IMAGES", Category.STORAGE, 4, "read your photos");
        add("READ_MEDIA_VIDEO", Category.STORAGE, 3, "read your videos");
        add("READ_MEDIA_AUDIO", Category.STORAGE, 2, "read your audio files");
        add("READ_EXTERNAL_STORAGE", Category.STORAGE, 4, "read shared storage (photos, documents)");
        add("WRITE_EXTERNAL_STORAGE", Category.STORAGE, 3, "write to shared storage");
        add("MANAGE_EXTERNAL_STORAGE", Category.STORAGE, 10, "access ALL files on the device");

        // 08 Background & persistence
        add("RECEIVE_BOOT_COMPLETED", Category.BACKGROUND, 4, "start itself when the phone boots");
        add("FOREGROUND_SERVICE", Category.BACKGROUND, 2, "keep running in the background");
        add("REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", Category.BACKGROUND, 6, "ask to skip battery limits so it is never stopped");
        add("WAKE_LOCK", Category.BACKGROUND, 1, "keep the phone awake");
        add("SCHEDULE_EXACT_ALARM", Category.BACKGROUND, 1, "wake itself up at exact times");

        // 09 Network
        add("INTERNET", Category.NETWORK, 1, "use the internet");
        add("ACCESS_NETWORK_STATE", Category.NETWORK, 1, "see network status");
        add("ACCESS_WIFI_STATE", Category.NETWORK, 1, "see Wi-Fi details");
        add("CHANGE_NETWORK_STATE", Category.NETWORK, 1, "change network connectivity");
    }

    public static Entry get(String permission) {
        return MAP.get(permission);
    }

    /** Special-access style permissions: granted through separate settings screens. */
    public static boolean isSpecialAccess(String permission) {
        Entry e = MAP.get(permission);
        return (e != null && e.category == Category.SPECIAL)
                || "android.permission.MANAGE_EXTERNAL_STORAGE".equals(permission)
                || "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS".equals(permission)
                || "android.permission.SCHEDULE_EXACT_ALARM".equals(permission)
                || "android.permission.WRITE_SETTINGS".equals(permission);
    }

    /** Sensitive = anything we categorise except the low-risk network group. Used for update diffs. */
    public static boolean isSensitive(String permission) {
        Entry e = MAP.get(permission);
        return e != null && e.category != Category.NETWORK
                && !"android.permission.WAKE_LOCK".equals(permission)
                && !"android.permission.FOREGROUND_SERVICE".equals(permission);
    }

    private PermissionCatalog() {
    }
}
