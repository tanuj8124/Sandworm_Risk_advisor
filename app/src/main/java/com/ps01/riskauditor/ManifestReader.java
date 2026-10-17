/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 *
 * Reads the <action> names from an installed APK's binary AndroidManifest.xml, which is
 * the "intents" half of the ML feature vector. antimalwareapp gets these through the hidden
 * AssetManager.addAssetPath() API, which newer Android blocks; here the APK is opened as a
 * zip (read-only, on device) and the compiled XML is decoded directly.
 */
package com.ps01.riskauditor;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

final class ManifestReader {

    private static final int RES_XML_TYPE = 0x0003;
    private static final int RES_STRING_POOL_TYPE = 0x0001;
    private static final int RES_XML_RESOURCE_MAP_TYPE = 0x0180;
    private static final int RES_XML_START_ELEMENT_TYPE = 0x0102;
    private static final int RES_XML_END_ELEMENT_TYPE = 0x0103;
    private static final Set<String> COMPONENT_TAGS = new HashSet<>(Arrays.asList(
            "activity", "activity-alias", "service", "receiver", "provider"));

    /** Everything we read from the binary manifest. */
    static final class Info {
        /** All intent-filter actions anywhere in the manifest (ML features). */
        final Set<String> actions = new LinkedHashSet<>();
        /** Component class name (as written in the manifest) → its intent-filter actions. */
        final Map<String, List<String>> componentActions = new LinkedHashMap<>();
        /** uses-permission names (used when inspecting APK files that are not installed). */
        final Set<String> permissions = new LinkedHashSet<>();
        /** The manifest's package attribute, if present. */
        String packageName;
    }
    private static final int ATTR_NAME_RES_ID = 0x01010003; // android:name
    private static final int TYPE_STRING = 0x03;

    private ManifestReader() {
    }

    /** All intent-filter action names declared in the APK's manifest. Empty on any error. */
    static Set<String> readActions(String apkPath) {
        return read(apkPath).actions;
    }

    /** Actions plus which component declares them. Empty on any error. */
    static Info read(String apkPath) {
        Info out = new Info();
        if (apkPath == null) return out;
        try (ZipFile zf = new ZipFile(apkPath)) {
            ZipEntry e = zf.getEntry("AndroidManifest.xml");
            if (e == null) return out;
            try (InputStream in = zf.getInputStream(e)) {
                parse(readAll(in), out);
            }
        } catch (Exception ignored) {
            // Unreadable or unusual manifest: the model simply sees fewer features.
        }
        return out;
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[16 * 1024];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    static void parse(byte[] data, Set<String> actionsOut) {
        Info info = new Info();
        parse(data, info);
        actionsOut.addAll(info.actions);
    }

    static void parse(byte[] data, Info out) {
        ByteBuffer b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if (data.length < 8 || (b.getShort(0) & 0xFFFF) != RES_XML_TYPE) return;
        int end = Math.min(b.getInt(4), data.length);
        int pos = b.getShort(2) & 0xFFFF;
        String[] strings = new String[0];
        int[] resIds = new int[0];
        String currentComponent = null;
        String currentTag = null;

        while (pos + 8 <= end) {
            int type = b.getShort(pos) & 0xFFFF;
            int headerSize = b.getShort(pos + 2) & 0xFFFF;
            int size = b.getInt(pos + 4);
            if (size < 8 || pos + size > end) break;

            if (type == RES_STRING_POOL_TYPE) {
                strings = readStringPool(b, pos, headerSize);
            } else if (type == RES_XML_RESOURCE_MAP_TYPE) {
                int n = (size - headerSize) / 4;
                resIds = new int[n];
                for (int i = 0; i < n; i++) resIds[i] = b.getInt(pos + headerSize + 4 * i);
            } else if (type == RES_XML_START_ELEMENT_TYPE) {
                int ext = pos + headerSize;
                String tag = str(strings, b.getInt(ext + 4));
                if ("action".equals(tag)) {
                    String v = nameAttr(b, ext, strings, resIds);
                    if (v != null) {
                        out.actions.add(v);
                        if (currentComponent != null) out.componentActions.get(currentComponent).add(v);
                    }
                } else if ("uses-permission".equals(tag) || "uses-permission-sdk-23".equals(tag)) {
                    String v = nameAttr(b, ext, strings, resIds);
                    if (v != null) out.permissions.add(v);
                } else if ("manifest".equals(tag)) {
                    out.packageName = attrByName(b, ext, strings, "package");
                } else if (tag != null && COMPONENT_TAGS.contains(tag)) {
                    String v = nameAttr(b, ext, strings, resIds);
                    if (v != null) {
                        currentComponent = v;
                        currentTag = tag;
                        if (!out.componentActions.containsKey(v)) out.componentActions.put(v, new ArrayList<>());
                    }
                }
            } else if (type == RES_XML_END_ELEMENT_TYPE) {
                String tag = str(strings, b.getInt(pos + headerSize + 4));
                if (tag != null && tag.equals(currentTag)) {
                    currentComponent = null;
                    currentTag = null;
                }
            }
            pos += size;
        }
    }

    /** Value of android:name on the element whose attribute extension starts at ext. */
    private static String nameAttr(ByteBuffer b, int ext, String[] strings, int[] resIds) {
        int attrStart = b.getShort(ext + 8) & 0xFFFF;
        int attrSize = b.getShort(ext + 10) & 0xFFFF;
        int attrCount = b.getShort(ext + 12) & 0xFFFF;
        for (int i = 0; i < attrCount; i++) {
            int a = ext + attrStart + i * attrSize;
            int nameIdx = b.getInt(a + 4);
            boolean isName = "name".equals(str(strings, nameIdx))
                    || (nameIdx >= 0 && nameIdx < resIds.length && resIds[nameIdx] == ATTR_NAME_RES_ID);
            if (!isName) continue;
            int raw = b.getInt(a + 8);
            int dataType = b.get(a + 15) & 0xFF;
            String v = raw >= 0 ? str(strings, raw)
                    : (dataType == TYPE_STRING ? str(strings, b.getInt(a + 16)) : null);
            if (v != null && !v.isEmpty()) return v;
        }
        return null;
    }

    /** Value of a plain (non-resource) string attribute such as package="…". */
    private static String attrByName(ByteBuffer b, int ext, String[] strings, String wanted) {
        int attrStart = b.getShort(ext + 8) & 0xFFFF;
        int attrSize = b.getShort(ext + 10) & 0xFFFF;
        int attrCount = b.getShort(ext + 12) & 0xFFFF;
        for (int i = 0; i < attrCount; i++) {
            int a = ext + attrStart + i * attrSize;
            if (!wanted.equals(str(strings, b.getInt(a + 4)))) continue;
            int raw = b.getInt(a + 8);
            int dataType = b.get(a + 15) & 0xFF;
            return raw >= 0 ? str(strings, raw) : (dataType == TYPE_STRING ? str(strings, b.getInt(a + 16)) : null);
        }
        return null;
    }

    private static String str(String[] pool, int idx) {
        return idx >= 0 && idx < pool.length ? pool[idx] : null;
    }

    private static String[] readStringPool(ByteBuffer b, int pos, int headerSize) {
        int count = b.getInt(pos + 8);
        int flags = b.getInt(pos + 16);
        int stringsStart = b.getInt(pos + 20);
        boolean utf8 = (flags & (1 << 8)) != 0;
        String[] res = new String[Math.max(0, count)];
        for (int i = 0; i < res.length; i++) {
            try {
                int o = pos + stringsStart + b.getInt(pos + headerSize + 4 * i);
                if (utf8) {
                    o += (b.get(o) & 0x80) != 0 ? 2 : 1;          // length in UTF-16 units (skip)
                    int len = b.get(o) & 0xFF;                      // length in bytes
                    if ((len & 0x80) != 0) {
                        len = ((len & 0x7F) << 8) | (b.get(o + 1) & 0xFF);
                        o += 2;
                    } else {
                        o += 1;
                    }
                    res[i] = new String(b.array(), o, len, StandardCharsets.UTF_8);
                } else {
                    int len = b.getShort(o) & 0xFFFF;
                    if ((len & 0x8000) != 0) {
                        len = ((len & 0x7FFF) << 16) | (b.getShort(o + 2) & 0xFFFF);
                        o += 4;
                    } else {
                        o += 2;
                    }
                    res[i] = new String(b.array(), o, len * 2, StandardCharsets.UTF_16LE);
                }
            } catch (RuntimeException e) {
                res[i] = "";
            }
        }
        return res;
    }
}
