/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 * Network monitor screen: start/stop the local DNS VPN and watch, live, which app
 * contacts which server. Suspicious destinations are highlighted.
 */
package com.ps01.riskauditor;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.Switch;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class NetworkActivity extends Activity {

    private static final int REQ_VPN = 11;

    private TextView status, warning, counts;
    private Button toggle;
    private boolean onlySuspicious = false;
    private final EventAdapter adapter = new EventAdapter();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private boolean refreshQueued = false;

    private final Runnable listener = () -> {
        synchronized (this) {
            if (refreshQueued) return;
            refreshQueued = true;
        }
        ui.postDelayed(() -> {
            synchronized (NetworkActivity.this) {
                refreshQueued = false;
            }
            refresh();
        }, 300);
    };

    public static Intent intent(Context c) {
        return new Intent(c, NetworkActivity.class);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getActionBar() != null) getActionBar().setDisplayHomeAsUpEnabled(true);
        setTitle("Network monitor");

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundResource(R.drawable.card);
        card.setPadding(dp(14), dp(14), dp(14), dp(14));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(dp(12), dp(12), dp(12), dp(6));

        card.addView(text("See which servers each app talks to", 17, true, getColor(R.color.primary)));
        card.addView(text("Runs a local VPN on this phone that only watches DNS lookups (the server names apps ask for). "
                + "Traffic is not changed or read and nothing leaves the device. Flags message-bot, tunnel and "
                + "throwaway servers that SMS-stealing malware uses to send your data out.",
                13, false, getColor(R.color.text_secondary)));
        status = text("", 14, true, getColor(R.color.primary));
        status.setPadding(0, dp(8), 0, 0);
        card.addView(status);
        warning = text("", 13, false, getColor(R.color.band_high));
        card.addView(warning);
        counts = text("", 12, false, getColor(R.color.text_secondary));
        card.addView(counts);

        LinearLayout buttons = new LinearLayout(this);
        toggle = new Button(this);
        toggle.setAllCaps(false);
        toggle.setOnClickListener(v -> {
            if (NetLog.running) stopMonitor();
            else startMonitor();
        });
        buttons.addView(toggle, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        Button clear = new Button(this);
        clear.setAllCaps(false);
        clear.setText("Clear log");
        clear.setOnClickListener(v -> NetLog.clear(this));
        buttons.addView(clear, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        card.addView(buttons);

        Switch sw = new Switch(this);
        sw.setText("Show only suspicious");
        sw.setOnCheckedChangeListener((b, checked) -> {
            onlySuspicious = checked;
            refresh();
        });
        card.addView(sw);
        root.addView(card, lp);

        ListView list = new ListView(this);
        list.setDivider(null);
        list.setAdapter(adapter);
        list.setOnItemClickListener((parent, view, position, id) -> {
            NetLog.Event e = adapter.getItem(position);
            if (e.pkg.contains(".")) startActivity(DetailActivity.intent(this, e.pkg));
        });
        root.addView(list, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(root);
    }

    @Override
    protected void onResume() {
        super.onResume();
        NetLog.addListener(listener);
        refresh();
    }

    @Override
    protected void onPause() {
        NetLog.removeListener(listener);
        super.onPause();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void startMonitor() {
        Intent prep = VpnService.prepare(this);
        if (prep != null) {
            startActivityForResult(prep, REQ_VPN); // system "connection request" dialog
        } else {
            onActivityResult(REQ_VPN, RESULT_OK, null);
        }
    }

    private void stopMonitor() {
        startService(new Intent(this, NetMonitorService.class).setAction(NetMonitorService.ACTION_STOP));
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) {
            startService(new Intent(this, NetMonitorService.class).setAction(NetMonitorService.ACTION_START));
        } else if (requestCode == REQ_VPN) {
            NetLog.status = "VPN permission was not given";
            refresh();
        }
    }

    private void refresh() {
        toggle.setText(NetLog.running ? "Stop monitoring" : "Start monitoring");
        status.setText(NetLog.running ? "● " + NetLog.status : "○ " + NetLog.status);
        status.setTextColor(NetLog.running ? getColor(R.color.band_low) : getColor(R.color.text_secondary));
        String w = NetLog.warning;
        warning.setVisibility(w == null ? View.GONE : View.VISIBLE);
        if (w != null) warning.setText("⚠ " + w);
        List<NetLog.Event> all = NetLog.recent(false);
        int suspicious = 0;
        for (NetLog.Event e : all) if (e.kind.suspicious()) suspicious++;
        counts.setText(all.size() + " lookups logged · " + suspicious + " suspicious");
        adapter.set(onlySuspicious ? NetLog.recent(true) : all);
    }

    private final class EventAdapter extends BaseAdapter {
        private List<NetLog.Event> items = new ArrayList<>();
        private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss", Locale.US);

        void set(List<NetLog.Event> items) {
            this.items = items;
            notifyDataSetChanged();
        }

        @Override
        public int getCount() {
            return items.size();
        }

        @Override
        public NetLog.Event getItem(int position) {
            return items.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            LinearLayout row;
            TextView top, domain, why;
            if (convertView == null) {
                row = new LinearLayout(NetworkActivity.this);
                row.setOrientation(LinearLayout.VERTICAL);
                row.setPadding(dp(16), dp(8), dp(16), dp(8));
                top = text("", 12, false, getColor(R.color.text_secondary));
                domain = text("", 14, true, getColor(R.color.primary));
                domain.setTypeface(Typeface.create(Typeface.MONOSPACE, Typeface.BOLD));
                why = text("", 12, false, getColor(R.color.band_critical));
                row.addView(top);
                row.addView(domain);
                row.addView(why);
            } else {
                row = (LinearLayout) convertView;
                top = (TextView) row.getChildAt(0);
                domain = (TextView) row.getChildAt(1);
                why = (TextView) row.getChildAt(2);
            }
            NetLog.Event e = items.get(position);
            top.setText(fmt.format(new Date(e.time)) + "  ·  " + e.label);
            domain.setText(e.domain);
            int color = e.kind.suspicious() ? getColor(R.color.band_critical)
                    : e.kind == DomainIntel.Kind.TRACKER ? getColor(R.color.band_medium) : getColor(R.color.primary);
            domain.setTextColor(color);
            if (e.kind == DomainIntel.Kind.NORMAL) {
                why.setVisibility(View.GONE);
            } else {
                why.setVisibility(View.VISIBLE);
                why.setText(e.kind.meaning);
                why.setTextColor(color);
            }
            return row;
        }
    }

    private TextView text(String s, int sp, boolean bold, int color) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
