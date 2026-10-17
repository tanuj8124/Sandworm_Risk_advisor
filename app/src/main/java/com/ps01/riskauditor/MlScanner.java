/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 *
 * On-device ML check (stretch 13). Uses the TensorFlow Lite model and feature list from
 * Project Matris AntiMalwareApp / LibreAV (https://github.com/projectmatris/antimalwareapp,
 * GPL-3.0): a 2000-slot 0/1 vector — 489 permissions followed by 1511 intent actions —
 * fed to a small neural network (2000 → 32 → 1, sigmoid) that outputs a malware probability.
 * Thresholds match the original app: > 0.75 malware, > 0.5 risky.
 *
 * The ML verdict is shown beside the rule score; the rule score remains the source of the
 * plain-language explanations.
 */
package com.ps01.riskauditor;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;
import org.tensorflow.lite.Interpreter;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

final class MlScanner {

    static final String MODEL_ASSET = "malware_model.tflite";
    static final String FEATURES_ASSET = "malware_features.json";
    static final float MALWARE = 0.75f;
    static final float RISKY = 0.5f;

    static final class Result {
        final float probability; // -1 when not available
        final int matched;       // how many of the model's features this app has
        final String verdict;

        Result(float probability, int matched, String verdict) {
            this.probability = probability;
            this.matched = matched;
            this.verdict = verdict;
        }
    }

    private static MlScanner instance;

    private Interpreter tflite;
    private final Map<String, Integer> permIndex = new HashMap<>();
    private final Map<String, Integer> intentIndex = new HashMap<>();
    private int inputSize = 2000;
    private String loadError;

    static synchronized MlScanner get(Context c) {
        if (instance == null) instance = new MlScanner(c.getApplicationContext());
        return instance;
    }

    private MlScanner(Context ctx) {
        try {
            JSONObject f = new JSONObject(new String(readAsset(ctx, FEATURES_ASSET), StandardCharsets.UTF_8));
            JSONArray perms = f.getJSONArray("permissions");
            JSONArray intents = f.getJSONArray("intents");
            for (int i = 0; i < perms.length(); i++) permIndex.put(perms.getString(i), i);
            // Intents follow the permissions in the vector (offset 489 in the original app).
            for (int i = 0; i < intents.length(); i++) intentIndex.put(intents.getString(i), perms.length() + i);

            byte[] model = readAsset(ctx, MODEL_ASSET);
            ByteBuffer buf = ByteBuffer.allocateDirect(model.length).order(ByteOrder.nativeOrder());
            buf.put(model);
            buf.rewind();
            tflite = new Interpreter(buf);
            int[] shape = tflite.getInputTensor(0).shape();
            inputSize = shape[shape.length - 1];
        } catch (Throwable t) {
            tflite = null;
            loadError = t.getClass().getSimpleName();
        }
    }

    boolean available() {
        return tflite != null;
    }

    synchronized Result predict(Collection<String> permissions, Collection<String> actions) {
        if (tflite == null) return new Result(-1f, 0, "AI model unavailable" + (loadError == null ? "" : " (" + loadError + ")"));
        float[][] input = new float[1][inputSize];
        int matched = 0;
        for (String p : permissions) {
            Integer i = permIndex.get(p);
            if (i != null && i < inputSize && input[0][i] == 0f) {
                input[0][i] = 1f;
                matched++;
            }
        }
        for (String a : actions) {
            Integer i = intentIndex.get(a);
            if (i != null && i < inputSize && input[0][i] == 0f) {
                input[0][i] = 1f;
                matched++;
            }
        }
        if (matched == 0) return new Result(-1f, 0, "Not enough data");
        float[][] output = new float[1][1];
        try {
            tflite.run(input, output);
        } catch (Exception e) {
            return new Result(-1f, matched, "AI check failed");
        }
        float p = output[0][0];
        return new Result(p, matched, verdictFor(p));
    }

    static String verdictFor(float p) {
        if (p < 0) return "No AI verdict";
        if (p > MALWARE) return "Malware-like";
        if (p > RISKY) return "Suspicious";
        return "Looks safe";
    }

    private static byte[] readAsset(Context ctx, String name) throws Exception {
        try (InputStream in = ctx.getAssets().open(name)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] b = new byte[16 * 1024];
            int n;
            while ((n = in.read(b)) > 0) bos.write(b, 0, n);
            return bos.toByteArray();
        }
    }
}
