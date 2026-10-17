/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 * Everything we learn about one installed app, plus its risk result.
 */
package com.ps01.riskauditor;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AppReport {

    public enum Band {
        LOW("Low", R.color.band_low),
        MEDIUM("Medium", R.color.band_medium),
        HIGH("High", R.color.band_high),
        CRITICAL("Critical", R.color.band_critical);

        public final String label;
        public final int colorRes;

        Band(String label, int colorRes) {
            this.label = label;
            this.colorRes = colorRes;
        }

        public static Band of(int score) {
            if (score >= 75) return CRITICAL;
            if (score >= 50) return HIGH;
            if (score >= 25) return MEDIUM;
            return LOW;
        }
    }

    /** What the user can do about a reason, mapped to a settings screen in DetailActivity. */
    public enum Fix {
        NONE, APP_SETTINGS, ACCESSIBILITY, DEVICE_ADMIN, NOTIFICATION_LISTENER, OVERLAY,
        UNKNOWN_SOURCES, USAGE_ACCESS, ALL_FILES, UNINSTALL
    }

    public static class Reason {
        public final int points;
        public final String text;
        public final Fix fix;

        public Reason(int points, String text, Fix fix) {
            this.points = points;
            this.text = text;
            this.fix = fix;
        }
    }

    public static class Perm {
        public final String name;
        public final boolean granted;
        /** normal / dangerous / signature / special / unknown */
        public final String protection;
        public final PermissionCatalog.Category category; // null if not in the nine categories

        public Perm(String name, boolean granted, String protection, PermissionCatalog.Category category) {
            this.name = name;
            this.granted = granted;
            this.protection = protection;
            this.category = category;
        }

        public String shortName() {
            int i = name.lastIndexOf('.');
            return i >= 0 ? name.substring(i + 1) : name;
        }
    }

    // ---- Inventory ----
    public String packageName;
    public String label;
    public String versionName;
    public long versionCode;
    public long firstInstallTime;
    public long lastUpdateTime;
    public String installerPackage;   // may be null
    public String installerLabel;
    public boolean sideloaded;
    public int targetSdk;
    public int playCategory = -1;     // ApplicationInfo.category
    public boolean isSystem;
    public String apkPath;

    // ---- Static manifest checks ----
    public boolean debuggable;
    public boolean cleartextAllowed;
    public int exportedUnprotected;   // services / receivers / providers exported without a permission

    // ---- Permissions ----
    public final List<Perm> perms = new ArrayList<>();
    public final Set<String> declared = new LinkedHashSet<>();
    public final Set<String> granted = new LinkedHashSet<>();

    // ---- Special access (live state) ----
    public boolean accessibilityDeclared, accessibilityEnabled;
    public boolean adminDeclared, adminActive;
    public boolean notifListenerDeclared, notifListenerEnabled;
    public boolean overlayDeclared, overlayGranted;
    public boolean installDeclared, installGranted;
    public boolean usageDeclared, usageGranted;
    public boolean allFilesDeclared, allFilesGranted;

    // ---- AI model (antimalwareapp TFLite) ----
    public final java.util.List<String> manifestPermissions = new ArrayList<>();
    public final Set<String> manifestActions = new LinkedHashSet<>();
    /** Malware probability 0..1, or -1 when the model could not judge this app. */
    public float mlProbability = -1f;
    public int mlMatched;
    public String mlVerdict = "No AI verdict";

    public boolean mlFlagged() {
        return mlProbability > MlScanner.RISKY;
    }

    public String mlShort() {
        return mlProbability < 0 ? "AI: n/a" : "AI: " + Math.round(mlProbability * 100) + "% " + mlVerdict.toLowerCase();
    }

    /** True when the model and the rule score clearly disagree — worth a manual look. */
    public boolean aiDisagrees() {
        if (mlProbability < 0) return false;
        boolean rulesLow = band.ordinal() <= Band.MEDIUM.ordinal();
        return (mlProbability > MlScanner.MALWARE && rulesLow) || (mlProbability < 0.2f && band == Band.CRITICAL);
    }

    // ---- Hidden icon / network monitor ----
    public boolean hasLauncherIcon = true;
    public boolean isKeyboard = false;
    /** Suspicious domains this app was seen contacting while the network monitor ran. */
    public final java.util.Map<String, DomainIntel.Kind> netFlags = new java.util.LinkedHashMap<>();

    // ---- Update diff ----
    public final Set<String> addedOnUpdate = new LinkedHashSet<>();

    // ---- Risk result ----
    public int score;
    public Band band = Band.LOW;
    public final List<Reason> reasons = new ArrayList<>();
    /** Points contributed per category (for summaries). */
    public final Map<PermissionCatalog.Category, Integer> categoryPoints = new EnumMap<>(PermissionCatalog.Category.class);
    /** Categories where the app actually holds (granted) access. */
    public final Set<PermissionCatalog.Category> grantedCategories = new LinkedHashSet<>();

    public boolean has(String perm) {
        return declared.contains(perm);
    }

    public boolean hasGranted(String perm) {
        return granted.contains(perm);
    }

    public String topReason() {
        return reasons.isEmpty() ? "No risky access found" : reasons.get(0).text;
    }
}
