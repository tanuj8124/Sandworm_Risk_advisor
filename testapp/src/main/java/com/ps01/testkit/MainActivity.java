package com.ps01.testkit;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.net.InetAddress;

/** Harmless test target for App Risk Auditor. Does nothing harmful. */
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(40, 40, 40, 40);
        TextView t = new TextView(this);
        t.setText("Super Torch (TEST APP)\n\nThis app only declares risky permissions so App Risk Auditor can flag it. "
                + "It contains no code that reads, records or sends anything.\n");
        root.addView(t);

        TextView result = new TextView(this);
        Button b1 = new Button(this);
        b1.setText("Demo: look up api.telegram.org");
        // Only a DNS name lookup — no connection is opened and no data is sent.
        // Lets the auditor's network monitor show a "suspicious server" alert live.
        b1.setOnClickListener(v -> new Thread(() -> {
            String msg;
            try {
                msg = "Looked up api.telegram.org → " + InetAddress.getByName("api.telegram.org").getHostAddress();
            } catch (Exception e) {
                msg = "Lookup failed: " + e.getMessage();
            }
            final String m = msg;
            runOnUiThread(() -> result.setText(m));
        }).start());
        root.addView(b1);
        root.addView(result);
        setContentView(root);
    }
}
