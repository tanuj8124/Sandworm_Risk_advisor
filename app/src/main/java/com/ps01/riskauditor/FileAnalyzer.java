/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 *
 * Content-based file checker. Looks at what a file REALLY is (its magic bytes and
 * internal structure), not just its name, and explains anything risky in plain words:
 *   - Windows programs, Linux/Android native binaries, loose DEX code
 *   - APK installers: permissions, special access and the on-device AI verdict
 *   - Office files: VBA macros, remote-template injection, Follina-style links, DDE, embedded objects
 *   - PDFs: JavaScript, auto-run actions, launch actions, embedded files
 *   - RTF exploit objects, Windows shortcuts (.lnk), scripts that download-and-run code
 *   - Archives: dangerous files inside, password protection
 *   - Disguised names (invoice.pdf.exe, hidden right-to-left override) and type mismatches
 *   - The EICAR antivirus test file
 * Pure Java with no Android imports, so it can be unit-tested on a PC.
 * Nothing is uploaded; files are only read.
 */
package com.ps01.riskauditor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

public final class FileAnalyzer {

    public static final int INFO = 0, MEDIUM = 1, HIGH = 2, CRITICAL = 3;
    public static final String[] SEVERITY_LABEL = {"Info", "Medium", "High", "Critical"};

    /** Opens a fresh stream on the file each time (works for java.io.File and content:// URIs). */
    public interface Source {
        InputStream open() throws IOException;
    }

    /** Optional hook to the on-device AI model for APK files. Returns -1 if unavailable. */
    public interface ApkJudge {
        float malwareProbability(Collection<String> permissions, Collection<String> actions);
    }

    public static volatile ApkJudge apkJudge = null;

    public static final class Finding {
        public final int severity;
        public final String text;

        Finding(int severity, String text) {
            this.severity = severity;
            this.text = text;
        }
    }

    public static final class Result {
        public String name;
        public String location;   // path or URI, for display / delete
        public long size;
        public String kind = "File";
        public int severity = INFO;
        public final List<Finding> findings = new ArrayList<>();
        public String apkPackage; // when the file is an APK

        void add(int sev, String text) {
            for (Finding f : findings) if (f.text.equals(text)) return;
            findings.add(new Finding(sev, text));
            if (sev > severity) severity = sev;
        }

        public boolean flagged() {
            return severity >= MEDIUM;
        }

        public String top() {
            Finding best = null;
            for (Finding f : findings) if (best == null || f.severity > best.severity) best = f;
            return best == null ? "Nothing risky found" : best.text;
        }
    }

    // ------------------------------------------------------------------ lists

    static final int HEAD_MAX = 4 * 1024 * 1024;     // bytes read for pattern checks
    static final int ZIP_ENTRY_READ_MAX = 2 * 1024 * 1024;
    static final int ZIP_MAX_ENTRIES = 4000;

    static final Set<String> WIN_EXEC = set("exe", "dll", "scr", "com", "cpl", "msi", "msp", "pif", "gadget", "sys", "ocx");
    static final Set<String> WIN_SCRIPT = set("bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "reg", "scf", "inf", "lnk", "url", "iso", "img", "vhd", "vhdx", "msc", "jar");
    static final Set<String> UNIX_SCRIPT = set("sh", "bash", "py", "pl");
    static final Set<String> ANDROID = set("apk", "xapk", "apks", "apkm", "dex");
    static final Set<String> MACRO_EXT = set("docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppam", "ppsm", "sldm");
    /** Extensions people trust: an executable pretending to be one of these is a red flag. */
    static final Set<String> DECOY = set("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rtf",
            "jpg", "jpeg", "png", "gif", "webp", "heic", "mp4", "mp3", "mov", "wav", "m4a", "opus", "zip");

    private static final String[] SCRIPT_IOCS = {
            "powershell -e", "powershell.exe -e", "-encodedcommand", "frombase64string", "invoke-expression", "iex(",
            "iex (", "downloadstring", "downloadfile", "invoke-webrequest", "wscript.shell", "shell.application",
            "certutil -urlcache", "certutil.exe -urlcache", "bitsadmin /transfer", "mshta http", "regsvr32 /s /n /u /i:http",
            "rundll32 javascript", "createobject(\"msxml2.xmlhttp", "start-process", "| sh", "|sh", "| bash", "|bash",
            "chmod 777", "chmod +x", "su -c", "pm install", "busybox", "/system/bin/sh"};

    private FileAnalyzer() {
    }

    // ------------------------------------------------------------------ entry point

    public static Result analyze(String name, String location, long size, Source src) {
        Result r = new Result();
        r.name = name == null ? "?" : name;
        r.location = location;
        r.size = size;
        String lower = r.name.toLowerCase(Locale.ROOT);
        String ext = ext(lower);

        checkName(r, lower, ext);

        byte[] head;
        try (InputStream in = src.open()) {
            head = readUpTo(in, HEAD_MAX);
        } catch (Exception e) {
            r.add(INFO, "Could not read the file contents.");
            return r;
        }
        if (head.length == 0) {
            r.kind = "Empty file";
            return r;
        }

        if (containsEicar(head)) {
            r.kind = "Antivirus test file";
            r.add(CRITICAL, "EICAR antivirus test signature. This is a harmless standard test file used to check that scanners work.");
        }

        String kind = magic(head);
        switch (kind) {
            case "PE":
                r.kind = "Windows program";
                r.add(HIGH, "Windows program (.exe/.dll). It can't run on Android, but malware is often shared this way to infect a PC. You likely don't need it on your phone.");
                mismatch(r, ext, "a Windows program");
                break;
            case "ELF":
                r.kind = "Native program (ELF)";
                r.add(HIGH, "Native Linux/Android program sitting in your files. Normal apps keep these inside themselves; loose ones are typical of rooting tools and malware.");
                mismatch(r, ext, "a native program");
                break;
            case "DEX":
                r.kind = "Android code (DEX)";
                r.add(HIGH, "Raw Android app code (DEX) outside any app. Malware droppers download code like this and load it later.");
                mismatch(r, ext, "Android code");
                break;
            case "LNK":
                r.kind = "Windows shortcut";
                r.add(HIGH, "Windows shortcut file (.lnk). These are a common way to hide a command that runs PowerShell when opened on a PC.");
                break;
            case "OLE":
                analyzeOle(r, head, ext);
                break;
            case "PDF":
                analyzePdf(r, head);
                mismatchIfExecutableExt(r, ext);
                break;
            case "RTF":
                analyzeRtf(r, head);
                break;
            case "ZIP":
                analyzeZip(r, src, ext, head);
                break;
            case "RAR":
            case "7Z":
                r.kind = kind.equals("RAR") ? "RAR archive" : "7-Zip archive";
                r.add(INFO, "Compressed archive that can't be looked inside here. Be careful with what you extract from it.");
                break;
            default:
                analyzeTextual(r, head, ext);
        }

        if (lower.startsWith(".") && r.severity >= HIGH) {
            r.add(HIGH, "The file is hidden (its name starts with a dot), which is unusual for a file you downloaded yourself.");
        }
        return r;
    }

    // ------------------------------------------------------------------ name checks

    private static void checkName(Result r, String lower, String ext) {
        if (r.name.indexOf('\u202E') >= 0 || r.name.indexOf('\u202D') >= 0 || r.name.indexOf('\u200F') >= 0) {
            r.add(CRITICAL, "The name contains a hidden right-to-left character that flips how the name is shown, so a program can look like a photo or PDF.");
        }
        // double extension: something.pdf.exe  /  photo.jpg.apk
        String[] parts = lower.split("\\.");
        if (parts.length >= 3) {
            String inner = parts[parts.length - 2];
            if (DECOY.contains(inner) && (WIN_EXEC.contains(ext) || WIN_SCRIPT.contains(ext) || ANDROID.contains(ext))) {
                r.add(CRITICAL, "Disguised file: it is named like a ." + inner + " but is really a ." + ext + ". This trick is used to make people open malware.");
            }
        }
        if (lower.matches(".*\\.(pdf|docx?|xlsx?|jpg|jpeg|png|mp4)\\s{3,}.*")) {
            r.add(CRITICAL, "The name pads lots of spaces after a harmless-looking extension to hide the real one.");
        }
        if (WIN_SCRIPT.contains(ext)) {
            r.kind = "Script / shortcut (." + ext + ")";
            r.add(HIGH, "Windows script or shortcut type (." + ext + "). These run commands when opened on a PC and are a common malware attachment.");
        }
        if (MACRO_EXT.contains(ext)) {
            r.add(MEDIUM, "Office file type that can contain macros (." + ext + "). Never click \"Enable content\" on files you weren't expecting.");
        }
    }

    private static void mismatch(Result r, String ext, String what) {
        if (DECOY.contains(ext)) {
            r.add(CRITICAL, "Pretends to be a ." + ext + " file but is actually " + what + ". This is a disguised file.");
        }
    }

    private static void mismatchIfExecutableExt(Result r, String ext) {
        if (WIN_EXEC.contains(ext) || ANDROID.contains(ext)) {
            r.add(MEDIUM, "Named ." + ext + " but the contents are a PDF; the name and contents don't match.");
        }
    }

    // ------------------------------------------------------------------ magic

    static String magic(byte[] h) {
        if (startsWith(h, 'M', 'Z')) return "PE";
        if (startsWith(h, 0x7F, 'E', 'L', 'F')) return "ELF";
        if (startsWith(h, 'd', 'e', 'x', '\n')) return "DEX";
        if (startsWith(h, 'P', 'K', 3, 4) || startsWith(h, 'P', 'K', 5, 6)) return "ZIP";
        if (startsWith(h, 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)) return "OLE";
        if (startsWith(h, 0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0)) return "LNK";
        if (startsWith(h, 'R', 'a', 'r', '!')) return "RAR";
        if (startsWith(h, '7', 'z', 0xBC, 0xAF, 0x27, 0x1C)) return "7Z";
        if (startsWith(h, '{', '\\', 'r', 't')) return "RTF";
        if (indexOf(h, "%PDF".getBytes(StandardCharsets.US_ASCII), 0, Math.min(h.length, 1024)) >= 0) return "PDF";
        return "OTHER";
    }

    // ------------------------------------------------------------------ OLE (old Office / MSI)

    private static void analyzeOle(Result r, byte[] h, String ext) {
        r.kind = "Office document (old format)";
        if ("msi".equals(ext) || "msp".equals(ext)) {
            r.kind = "Windows installer (.msi)";
            r.add(HIGH, "Windows installer package. It can't run on Android but could install malware on a PC.");
            return;
        }
        if (containsUtf16(h, "_VBA_PROJECT") || containsUtf16(h, "VBA") && containsUtf16(h, "PROJECT")
                || containsAscii(h, "Attribute VB_Name")) {
            r.add(HIGH, "Contains VBA macros: code that runs when you click \"Enable content\". This is the most common way malicious Excel/Word files infect computers.");
            if (containsAsciiCI(h, "AutoOpen") || containsAsciiCI(h, "Auto_Open") || containsAsciiCI(h, "Workbook_Open")
                    || containsAsciiCI(h, "Document_Open")) {
                r.add(CRITICAL, "The macros are set to run automatically as soon as the document is opened.");
            }
            if (scriptIocs(h).size() > 0) {
                r.add(CRITICAL, "The macro code downloads or runs other programs (" + String.join(", ", scriptIocs(h)) + ").");
            }
        }
        if (containsUtf16(h, "\u0001Ole10Native") || containsUtf16(h, "ObjectPool")) {
            r.add(MEDIUM, "Contains an embedded file or object. Malicious documents hide programs inside like this.");
        }
        if (containsUtf16(h, "EncryptedPackage")) {
            r.add(MEDIUM, "Password-protected Office file. Scanners can't look inside, which is why attackers send files like this with the password in the message.");
        }
        if (containsAscii(h, "Excel 4.0") || containsUtf16(h, "Macro1") || containsAsciiCI(h, "EXEC(")) {
            r.add(HIGH, "Looks like it contains old Excel 4.0 (XLM) macros, often abused by malware.");
        }
    }

    // ------------------------------------------------------------------ PDF

    private static void analyzePdf(Result r, byte[] h) {
        r.kind = "PDF document";
        String s = decodePdfNames(new String(h, StandardCharsets.ISO_8859_1));
        boolean js = s.contains("/JavaScript") || s.matches("(?s).*/JS[\\s(<\\[/].*");
        boolean auto = s.contains("/OpenAction") || s.contains("/AA");
        if (s.contains("/Launch")) {
            r.add(CRITICAL, "Has a \"Launch\" action that tries to run a program or command when the PDF is opened.");
        }
        if (js) {
            r.add(auto ? CRITICAL : HIGH, auto
                    ? "Contains JavaScript that runs automatically when the PDF is opened. Normal PDFs almost never need this."
                    : "Contains JavaScript code. Normal PDFs (bills, tickets, forms) rarely need it.");
        }
        if (s.contains("/EmbeddedFile")) {
            r.add(MEDIUM, "Has a file attached inside the PDF. Check what it is before opening it.");
        }
        if (s.contains("/RichMedia") || s.contains("/XFA")) {
            r.add(MEDIUM, "Uses rich media or XFA forms, features that have been abused by PDF exploits.");
        }
        if (s.contains("/SubmitForm") && s.contains("/URI")) {
            r.add(INFO, "Has a form that submits data to a web address.");
        }
    }

    /** PDF names can hide keywords with hex escapes like /J#61vaScript. */
    static String decodePdfNames(String s) {
        if (s.indexOf('#') < 0) return s;
        Matcher m = Pattern.compile("#([0-9A-Fa-f]{2})").matcher(s);
        StringBuffer sb = new StringBuffer();
        while (m.find()) m.appendReplacement(sb, Matcher.quoteReplacement(String.valueOf((char) Integer.parseInt(m.group(1), 16))));
        m.appendTail(sb);
        return sb.toString();
    }

    // ------------------------------------------------------------------ RTF

    private static void analyzeRtf(Result r, byte[] h) {
        r.kind = "RTF document";
        String s = new String(h, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
        if (s.contains("\\objdata") || s.contains("\\object")) {
            boolean equation = s.contains("equation") || s.contains("0002ce02");
            boolean autoUpdate = s.contains("\\objupdate");
            if (equation) {
                r.add(CRITICAL, "Embeds an Equation Editor object, the target of a very common Office exploit (CVE-2017-11882).");
            } else if (autoUpdate) {
                r.add(HIGH, "Embeds an object set to load automatically when the document opens.");
            } else {
                r.add(MEDIUM, "Contains an embedded object. Malicious RTF files use these to carry exploits.");
            }
        }
    }

    // ------------------------------------------------------------------ ZIP family (APK, OOXML, JAR, plain zip)

    /** Reads local-file headers straight from the bytes: works even when Java refuses encrypted entries. */
    static List<String[]> rawZipEntries(byte[] h) {
        List<String[]> out = new ArrayList<>();
        byte[] sig = {'P', 'K', 3, 4};
        int i = 0;
        while (out.size() < ZIP_MAX_ENTRIES && (i = indexOf(h, sig, i, h.length)) >= 0) {
            if (i + 30 > h.length) break;
            int flags = (h[i + 6] & 0xFF) | ((h[i + 7] & 0xFF) << 8);
            int nameLen = (h[i + 26] & 0xFF) | ((h[i + 27] & 0xFF) << 8);
            if (nameLen > 0 && i + 30 + nameLen <= h.length) {
                String n = new String(h, i + 30, nameLen, (flags & 0x800) != 0 ? StandardCharsets.UTF_8 : StandardCharsets.ISO_8859_1);
                out.add(new String[]{n, (flags & 1) != 0 ? "enc" : ""});
            }
            i += 4;
        }
        return out;
    }

    private static void analyzeZip(Result r, Source src, String ext, byte[] head) {
        List<String> names = new ArrayList<>();
        Set<String> nameSet = new HashSet<>();
        List<String> dangerousInside = new ArrayList<>();
        List<String> disguisedInside = new ArrayList<>();
        boolean encrypted = false;
        byte[] manifest = null;
        StringBuilder rels = new StringBuilder();
        StringBuilder docXml = new StringBuilder();
        boolean eicarInside = false;
        boolean truncated = false;

        try (ZipInputStream zin = new ZipInputStream(src.open())) {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                if (names.size() >= ZIP_MAX_ENTRIES) {
                    truncated = true;
                    break;
                }
                String n = e.getName();
                names.add(n);
                nameSet.add(n);
                String ln = n.toLowerCase(Locale.ROOT);
                if (e.isDirectory()) continue;
                byte[] data;
                try {
                    boolean wantAll = n.equals("AndroidManifest.xml") || ln.endsWith(".rels") || ln.equals("word/document.xml")
                            || ln.equals("[content_types].xml") || e.getSize() >= 0 && e.getSize() < 4096;
                    data = readUpTo(zin, wantAll ? ZIP_ENTRY_READ_MAX : 64);
                } catch (ZipException ze) {
                    String msg = String.valueOf(ze.getMessage()).toLowerCase(Locale.ROOT);
                    if (msg.contains("encrypt")) {
                        encrypted = true;
                        checkInnerName(ln, dangerousInside, disguisedInside, null);
                        continue;
                    }
                    throw ze;
                }
                if (n.equals("AndroidManifest.xml")) manifest = data;
                if (ln.endsWith(".rels")) rels.append(new String(data, StandardCharsets.UTF_8)).append('\n');
                if (ln.equals("word/document.xml")) docXml.append(new String(data, StandardCharsets.UTF_8));
                if (containsEicar(data)) eicarInside = true;
                checkInnerName(ln, dangerousInside, disguisedInside, data);
            }
        } catch (Exception ex) {
            // Java can't open encrypted entries at all; fall back to reading the headers ourselves
        }
        for (String[] raw : rawZipEntries(head)) {
            if (!"enc".equals(raw[1])) continue;
            encrypted = true;
            if (!nameSet.contains(raw[0])) {
                names.add(raw[0]);
                nameSet.add(raw[0]);
                checkInnerName(raw[0].toLowerCase(Locale.ROOT), dangerousInside, disguisedInside, null);
            }
        }
        if (names.isEmpty()) {
            r.kind = "Archive";
            r.add(INFO, "Damaged or unusual archive; it could not be opened.");
            return;
        }

        boolean isApk = nameSet.contains("AndroidManifest.xml") && (nameSet.contains("classes.dex") || hasPrefix(names, "classes"));
        boolean isOoxml = nameSet.contains("[Content_Types].xml");
        boolean isJar = !isApk && nameSet.contains("META-INF/MANIFEST.MF") && hasSuffix(names, ".class");

        if (isApk) {
            analyzeApk(r, manifest, ext);
        } else if (isOoxml) {
            analyzeOoxml(r, names, rels.toString(), docXml.toString(), ext);
        } else if (isJar) {
            r.kind = "Java program (.jar)";
            r.add(MEDIUM, "Java program. It can't run on Android directly, but .jar files are a common way to spread PC malware.");
        } else {
            r.kind = "ZIP archive";
            if ("apk".equals(ext) || "xapk".equals(ext)) {
                r.kind = "App bundle";
                if (hasSuffix(names, ".apk")) r.add(MEDIUM, "App bundle containing APK installers. Only install apps from trusted stores.");
            }
            if (DECOY.contains(ext) && !"zip".equals(ext)) {
                r.add(HIGH, "Named ." + ext + " but it is really a ZIP archive. The name and contents don't match.");
            }
        }

        if (encrypted) {
            r.add(dangerousInside.isEmpty() ? MEDIUM : HIGH,
                    "Password-protected archive. Scanners (including this one) can't look inside, which is exactly why attackers zip malware with a password and send the password separately.");
        }
        if (!dangerousInside.isEmpty()) {
            r.add(HIGH, "Contains program or script files: " + joinShort(dangerousInside) + ".");
        }
        if (!disguisedInside.isEmpty()) {
            r.add(CRITICAL, "Contains disguised files (fake extension): " + joinShort(disguisedInside) + ".");
        }
        if (eicarInside) {
            r.add(CRITICAL, "Contains the EICAR antivirus test file (harmless test signature).");
        }
        if (truncated) r.add(INFO, "Very large archive; only the first " + ZIP_MAX_ENTRIES + " entries were checked.");
    }

    private static void checkInnerName(String ln, List<String> dangerous, List<String> disguised, byte[] data) {
        String base = ln.substring(ln.lastIndexOf('/') + 1);
        if (base.isEmpty()) return;
        String e = ext(base);
        String m = data == null ? "OTHER" : magic(data);
        boolean exec = WIN_EXEC.contains(e) || WIN_SCRIPT.contains(e) || "PE".equals(m) || "ELF".equals(m) || "LNK".equals(m);
        boolean apk = "apk".equals(e) || "DEX".equals(m) && !base.startsWith("classes");
        // Normal files inside APK/JAR/Office packages are not interesting
        if (base.endsWith(".so") || base.endsWith(".class") || base.startsWith("classes") && base.endsWith(".dex")) return;
        if (exec || apk) {
            if (dangerous.size() < 50) dangerous.add(base);
        }
        String[] parts = base.split("\\.");
        if (parts.length >= 3 && DECOY.contains(parts[parts.length - 2]) && (exec || apk)) {
            if (disguised.size() < 50) disguised.add(base);
        } else if (("PE".equals(m) || "ELF".equals(m)) && DECOY.contains(e)) {
            if (disguised.size() < 50) disguised.add(base);
        }
    }

    // ------------------------------------------------------------------ APK

    private static void analyzeApk(Result r, byte[] manifest, String ext) {
        r.kind = "Android app installer (APK)";
        if (DECOY.contains(ext)) {
            r.add(CRITICAL, "Pretends to be a ." + ext + " file but is actually an Android app installer. This is a classic trick to get you to install malware.");
        }
        r.add(MEDIUM, "App installer file. Installing apps from outside an app store skips Google's checks.");
        if (manifest == null) return;
        ManifestReader.Info mi = new ManifestReader.Info();
        try {
            ManifestReader.parse(manifest, mi);
        } catch (Exception ignored) {
        }
        r.apkPackage = mi.packageName;
        Set<String> p = mi.permissions;
        Set<String> a = mi.actions;
        String P = "android.permission.";
        boolean sms = p.contains(P + "READ_SMS") || p.contains(P + "RECEIVE_SMS");
        boolean net = p.contains(P + "INTERNET");
        boolean boot = p.contains(P + "RECEIVE_BOOT_COMPLETED") || a.contains("android.intent.action.BOOT_COMPLETED");
        boolean acc = a.contains("android.accessibilityservice.AccessibilityService");
        boolean overlay = p.contains(P + "SYSTEM_ALERT_WINDOW");
        boolean admin = a.contains("android.app.action.DEVICE_ADMIN_ENABLED");
        boolean notif = a.contains("android.service.notification.NotificationListenerService");
        boolean install = p.contains(P + "REQUEST_INSTALL_PACKAGES");
        boolean smsReceiver = a.contains("android.provider.Telephony.SMS_RECEIVED");

        List<String> special = new ArrayList<>();
        if (acc) special.add("accessibility (read your screen)");
        if (admin) special.add("device admin");
        if (notif) special.add("notification reading");
        if (overlay) special.add("draw over other apps");
        if (install) special.add("install other apps");
        if (!special.isEmpty()) r.add(HIGH, "If installed, it would ask for special access: " + String.join(", ", special) + ".");
        if (sms && net && boot) {
            r.add(CRITICAL, "Built like an SMS-stealing banking trojan: reads SMS" + (smsReceiver ? " (listens for every new SMS)" : "")
                    + ", uses the internet and restarts at boot.");
        } else if (sms) {
            r.add(HIGH, "Would be able to read your SMS, including OTP codes.");
        }
        if (acc && overlay) r.add(CRITICAL, "Combines accessibility and screen overlay: the fake-login-screen attack used against banking apps.");

        ApkJudge judge = apkJudge;
        if (judge != null) {
            float prob = judge.malwareProbability(p, a);
            if (prob >= 0) {
                int pct = Math.round(prob * 100);
                if (prob > 0.75f) r.add(CRITICAL, "On-device AI model rates it " + pct + "% malware-like.");
                else if (prob > 0.5f) r.add(HIGH, "On-device AI model rates it " + pct + "% suspicious.");
                else r.add(INFO, "On-device AI model rates it " + pct + "% (looks safe).");
            }
        }
        if (r.apkPackage != null) r.add(INFO, "Package name: " + r.apkPackage + " · " + p.size() + " permissions requested.");
    }

    // ------------------------------------------------------------------ OOXML (docx / xlsx / pptx and macro variants)

    private static void analyzeOoxml(Result r, List<String> names, String rels, String docXml, String ext) {
        r.kind = "Office document";
        boolean vba = false, activeX = false, embedded = false;
        for (String n : names) {
            String ln = n.toLowerCase(Locale.ROOT);
            if (ln.endsWith("vbaproject.bin")) vba = true;
            if (ln.contains("/activex/")) activeX = true;
            if (ln.contains("/embeddings/")) embedded = true;
        }
        if (vba) {
            r.add(HIGH, "Contains VBA macros: code that runs when you click \"Enable content\". Malicious Excel/Word files work this way.");
            if (!MACRO_EXT.contains(ext) && ("docx".equals(ext) || "xlsx".equals(ext) || "pptx".equals(ext))) {
                r.add(CRITICAL, "Has macros hidden inside a normal ." + ext + " name, a sign of tampering.");
            }
        }
        String lr = rels.toLowerCase(Locale.ROOT);
        if (lr.contains("ms-msdt:") || lr.contains("mhtml:") || lr.contains("search-ms:") || lr.contains("ms-officecmd:")) {
            r.add(CRITICAL, "Links to a Windows system handler (ms-msdt/mhtml/search-ms). This is the \"Follina\" exploit pattern (CVE-2022-30190).");
        }
        if (lr.contains("targetmode=\"external\"") && (lr.contains("attachedtemplate") || lr.contains("/oleobject") || lr.contains("/frame"))
                && (lr.contains("http://") || lr.contains("https://") || lr.contains("file://") || lr.contains("\\\\"))) {
            r.add(HIGH, "Loads a template or object from the internet when opened (remote template injection), a way to pull in malicious macros later.");
        }
        String ld = docXml.toLowerCase(Locale.ROOT);
        if (ld.contains("ddeauto") || ld.contains(" dde ")) {
            r.add(HIGH, "Uses DDE fields, which can run commands when the document is opened.");
        }
        if (activeX) r.add(MEDIUM, "Contains ActiveX controls, which can run code on Windows.");
        if (embedded) r.add(MEDIUM, "Contains embedded files or objects. Malicious documents hide programs inside like this.");
    }

    // ------------------------------------------------------------------ text / scripts

    private static void analyzeTextual(Result r, byte[] h, String ext) {
        boolean shebang = startsWith(h, '#', '!');
        if (shebang && !UNIX_SCRIPT.contains(ext)) r.kind = "Script";
        if (shebang || UNIX_SCRIPT.contains(ext)) {
            r.kind = "Script";
            if (!"py".equals(ext) && !"pl".equals(ext)) r.add(MEDIUM, "Shell script. On Android these are used by rooting and malware tools.");
        }
        if (WIN_SCRIPT.contains(ext) || shebang || UNIX_SCRIPT.contains(ext) || isHtml(ext) || ext.equals("txt") || ext.isEmpty()) {
            List<String> iocs = scriptIocs(h);
            if (!iocs.isEmpty()) {
                r.add(CRITICAL, "The code downloads or runs other programs (" + String.join(", ", iocs) + ").");
            }
        }
        if (isHtml(ext)) {
            String s = new String(h, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
            if (s.contains("<input") && s.contains("type=\"password\"") && (s.contains("action=\"http") || s.contains("fetch(") || s.contains("xmlhttprequest"))) {
                r.kind = "Web page";
                r.add(HIGH, "Saved web page with a password form that sends data online, typical of phishing attachments.");
            }
            if (s.contains("atob(") && (s.contains("download") || s.contains("blob"))) {
                r.add(HIGH, "Web page that builds a file from hidden encoded data (HTML smuggling), used to sneak malware past filters.");
            }
        }
    }

    private static boolean isHtml(String ext) {
        return ext.equals("html") || ext.equals("htm") || ext.equals("shtml") || ext.equals("svg");
    }

    private static List<String> scriptIocs(byte[] h) {
        String s = new String(h, 0, Math.min(h.length, 1024 * 1024), StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
        Set<String> out = new LinkedHashSet<>();
        for (String ioc : SCRIPT_IOCS) {
            if (s.contains(ioc)) out.add(ioc.trim());
            if (out.size() >= 4) break;
        }
        return new ArrayList<>(out);
    }

    // ------------------------------------------------------------------ EICAR

    /** Built at runtime from two halves so this app's own APK doesn't trip other antivirus engines. */
    private static final byte[] EICAR_A = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] EICAR_B = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!".getBytes(StandardCharsets.US_ASCII);

    /** The full EICAR test file, assembled at runtime (used by the "create test file" button). */
    static byte[] eicarTestFile() {
        byte[] tail = {'$', 'H', '+', 'H', '*'};
        byte[] out = new byte[EICAR_A.length + EICAR_B.length + tail.length];
        System.arraycopy(EICAR_A, 0, out, 0, EICAR_A.length);
        System.arraycopy(EICAR_B, 0, out, EICAR_A.length, EICAR_B.length);
        System.arraycopy(tail, 0, out, EICAR_A.length + EICAR_B.length, tail.length);
        return out;
    }

    static boolean containsEicar(byte[] data) {
        int a = indexOf(data, EICAR_A, 0, Math.min(data.length, 4096));
        return a >= 0 && indexOf(data, EICAR_B, a, Math.min(data.length, a + 256)) >= 0;
    }

    // ------------------------------------------------------------------ byte helpers

    static String ext(String lowerName) {
        String n = lowerName.trim();
        int slash = n.lastIndexOf('/');
        if (slash >= 0) n = n.substring(slash + 1);
        int dot = n.lastIndexOf('.');
        return dot >= 0 && dot < n.length() - 1 ? n.substring(dot + 1).trim() : "";
    }

    static byte[] readUpTo(InputStream in, int max) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.min(max, 64 * 1024));
        byte[] buf = new byte[16 * 1024];
        int total = 0, n;
        while (total < max && (n = in.read(buf, 0, Math.min(buf.length, max - total))) > 0) {
            bos.write(buf, 0, n);
            total += n;
        }
        return bos.toByteArray();
    }

    private static boolean startsWith(byte[] h, int... sig) {
        if (h.length < sig.length) return false;
        for (int i = 0; i < sig.length; i++) if ((h[i] & 0xFF) != (sig[i] & 0xFF)) return false;
        return true;
    }

    static int indexOf(byte[] data, byte[] pat, int from, int to) {
        outer:
        for (int i = Math.max(0, from); i <= to - pat.length; i++) {
            for (int j = 0; j < pat.length; j++) if (data[i + j] != pat[j]) continue outer;
            return i;
        }
        return -1;
    }

    private static boolean containsAscii(byte[] h, String s) {
        return indexOf(h, s.getBytes(StandardCharsets.US_ASCII), 0, h.length) >= 0;
    }

    private static boolean containsAsciiCI(byte[] h, String s) {
        return new String(h, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT).contains(s.toLowerCase(Locale.ROOT));
    }

    private static boolean containsUtf16(byte[] h, String s) {
        return indexOf(h, s.getBytes(StandardCharsets.UTF_16LE), 0, h.length) >= 0;
    }

    private static boolean hasPrefix(List<String> names, String prefix) {
        for (String n : names) if (n.startsWith(prefix) && n.endsWith(".dex")) return true;
        return false;
    }

    private static boolean hasSuffix(List<String> names, String suffix) {
        for (String n : names) if (n.toLowerCase(Locale.ROOT).endsWith(suffix)) return true;
        return false;
    }

    private static String joinShort(List<String> items) {
        List<String> shown = items.subList(0, Math.min(5, items.size()));
        return String.join(", ", shown) + (items.size() > 5 ? " and " + (items.size() - 5) + " more" : "");
    }

    private static Set<String> set(String... s) {
        return new HashSet<>(Arrays.asList(s));
    }
}
