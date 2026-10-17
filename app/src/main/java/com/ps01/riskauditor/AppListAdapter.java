/*
 * App Risk Auditor (PS-01) — AGPL-3.0, see LICENSE.
 */
package com.ps01.riskauditor;

import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class AppListAdapter extends BaseAdapter {

    private final Context ctx;
    private final PackageManager pm;
    private final LayoutInflater inflater;
    private final Map<String, Drawable> icons = new HashMap<>();
    private List<AppReport> items = new ArrayList<>();

    AppListAdapter(Context ctx) {
        this.ctx = ctx;
        this.pm = ctx.getPackageManager();
        this.inflater = LayoutInflater.from(ctx);
    }

    void setItems(List<AppReport> items) {
        this.items = items;
        notifyDataSetChanged();
    }

    @Override
    public int getCount() {
        return items.size();
    }

    @Override
    public AppReport getItem(int position) {
        return items.get(position);
    }

    @Override
    public long getItemId(int position) {
        return items.get(position).packageName.hashCode();
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View v = convertView != null ? convertView : inflater.inflate(R.layout.item_app, parent, false);
        AppReport r = items.get(position);
        int color = ctx.getColor(r.band.colorRes);

        ((ImageView) v.findViewById(R.id.icon)).setImageDrawable(icon(r.packageName));
        ((TextView) v.findViewById(R.id.label)).setText(r.label);
        ((TextView) v.findViewById(R.id.pkg)).setText(r.packageName + (r.sideloaded ? "  ·  sideloaded" : ""));
        TextView reason = v.findViewById(R.id.reason);
        reason.setText(r.topReason());
        reason.setTextColor(r.band.ordinal() >= AppReport.Band.HIGH.ordinal() ? color : ctx.getColor(R.color.text_secondary));

        TextView score = v.findViewById(R.id.score);
        score.setText(String.valueOf(r.score));
        score.setTextColor(color);

        TextView band = v.findViewById(R.id.band);
        band.setText(r.band.label.toUpperCase());
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(color);
        bg.setCornerRadius(20f);
        band.setBackground(bg);

        TextView ai = v.findViewById(R.id.ai);
        if (r.mlProbability < 0) {
            ai.setText("AI –");
            ai.setTextColor(ctx.getColor(R.color.text_secondary));
        } else {
            ai.setText("AI " + Math.round(r.mlProbability * 100) + "%");
            ai.setTextColor(r.mlProbability > MlScanner.MALWARE ? ctx.getColor(R.color.band_critical)
                    : r.mlProbability > MlScanner.RISKY ? ctx.getColor(R.color.band_high) : ctx.getColor(R.color.band_low));
        }
        return v;
    }

    private Drawable icon(String pkg) {
        Drawable d = icons.get(pkg);
        if (d == null) {
            try {
                d = pm.getApplicationIcon(pkg);
            } catch (PackageManager.NameNotFoundException e) {
                d = pm.getDefaultActivityIcon();
            }
            icons.put(pkg, d);
        }
        return d;
    }
}
