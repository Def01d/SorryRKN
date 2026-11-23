package dev.graybridge;

import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.graphics.*;
import android.graphics.drawable.*;
import android.net.VpnService;
import android.os.*;
import android.text.*;
import android.util.LruCache;
import android.view.*;
import android.widget.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/** Per-app split-tunneling store and picker for both local bypass and remote VPN. */
final class AppExclusions {
    private static final String PREF_KEY = "excluded_apps";
    private static final int BG = Color.rgb(11, 11, 13);
    private static final int PANEL = Color.rgb(20, 20, 24);
    private static final int PANEL_ELEV = Color.rgb(28, 28, 34);
    private static final int WHITE = Color.rgb(242, 242, 245);
    private static final int GRAY = Color.rgb(142, 142, 152);
    private static final int DIM = Color.rgb(92, 92, 102);
    private static final int BORDER = Color.rgb(40, 40, 48);
    private static final int BORDER_STRONG = Color.rgb(60, 60, 72);
    private static final int GREEN = Color.rgb(52, 211, 153);
    private static final Pattern VALID_PACKAGE = Pattern.compile("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+$");

    private static final class AppItem {
        final ApplicationInfo info;
        final String packageName;
        final String label;
        final String searchKey;
        final boolean system;

        AppItem(ApplicationInfo info, String packageName, String label, boolean system) {
            this.info = info;
            this.packageName = packageName;
            this.label = label;
            this.searchKey = (label + " " + packageName).toLowerCase(Locale.ROOT);
            this.system = system;
        }
    }

    private AppExclusions() {}

    static LinkedHashSet<String> list(Context c) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        String raw = Settings.prefs(c).getString(PREF_KEY, "");
        String self = c.getPackageName();
        for (String line : raw.split("\n")) {
            String pkg = line.trim();
            if (!pkg.isEmpty() && !pkg.equals(self) && VALID_PACKAGE.matcher(pkg).matches()) {
                out.add(pkg);
            }
        }
        return out;
    }

    static int count(Context c) {
        return list(c).size();
    }

    static void save(Context c, Collection<String> packages) {
        ArrayList<String> valid = new ArrayList<>();
        HashSet<String> seen = new HashSet<>();
        String self = c.getPackageName();
        if (packages != null) {
            for (String item : packages) {
                if (item == null) continue;
                String pkg = item.trim();
                if (!pkg.isEmpty() && !pkg.equals(self) && VALID_PACKAGE.matcher(pkg).matches() && seen.add(pkg)) {
                    valid.add(pkg);
                }
            }
        }
        Collections.sort(valid);
        Settings.prefs(c).edit().putString(PREF_KEY, TextUtils.join("\n", valid)).apply();
    }

    static String summary(Context c) {
        int n = count(c);
        if (n == 0) return "Все приложения через защиту";
        int m100 = n % 100;
        int m10 = n % 10;
        String word;
        if (m100 >= 11 && m100 <= 14) word = "приложений";
        else if (m10 == 1) word = "приложение";
        else if (m10 >= 2 && m10 <= 4) word = "приложения";
        else word = "приложений";
        return "Исключено: " + n + " " + word;
    }

    static void applyToBuilder(Context c, VpnService.Builder builder) {
        for (String pkg : list(c)) {
            try {
                builder.addDisallowedApplication(pkg);
            } catch (PackageManager.NameNotFoundException ignored) {
                // App was uninstalled after being excluded; ignore safely.
            }
        }
    }

    static AlertDialog show(Activity activity, Runnable onSaved) {
        final float d = activity.getResources().getDisplayMetrics().density;
        final int pad = Math.round(18 * d);
        final LinkedHashSet<String> before = list(activity);
        final LinkedHashSet<String> selected = new LinkedHashSet<>(before);
        final PackageManager pm = activity.getPackageManager();
        final LruCache<String, Drawable> icons = new LruCache<>(120);

        LinearLayout root = new LinearLayout(activity);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(PANEL);
        root.setPadding(pad, Math.round(12 * d), pad, Math.round(8 * d));

        TextView note = new TextView(activity);
        note.setText("Выбранные приложения работают напрямую — без VPN, локального обхода DPI и Гео-DNS.");
        note.setTextSize(12);
        note.setTextColor(GRAY);
        root.addView(note);

        EditText search = new EditText(activity);
        search.setHint("Поиск по названию или пакету…");
        search.setHintTextColor(DIM);
        search.setTextColor(WHITE);
        search.setTextSize(14);
        search.setSingleLine(true);
        search.setPadding(Math.round(12 * d), Math.round(9 * d), Math.round(12 * d), Math.round(9 * d));
        search.setBackground(shape(BG, Math.round(10 * d), BORDER, d));
        LinearLayout.LayoutParams searchLp = new LinearLayout.LayoutParams(-1, -2);
        searchLp.topMargin = Math.round(10 * d);
        root.addView(search, searchLp);

        LinearLayout bar = new LinearLayout(activity);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams barLp = new LinearLayout.LayoutParams(-1, -2);
        barLp.topMargin = Math.round(10 * d);
        root.addView(bar, barLp);

        Switch sysSwitch = new Switch(activity);
        sysSwitch.setText("Системные  ");
        sysSwitch.setTextColor(GRAY);
        sysSwitch.setTextSize(12);
        bar.addView(sysSwitch);

        TextView counter = new TextView(activity);
        counter.setTextSize(12);
        counter.setTextColor(GREEN);
        counter.setGravity(Gravity.END);
        counter.setPadding(Math.round(8 * d), 0, Math.round(8 * d), 0);
        bar.addView(counter, new LinearLayout.LayoutParams(0, -2, 1));

        TextView clearBtn = new TextView(activity);
        clearBtn.setText("Сбросить");
        clearBtn.setTextSize(11);
        clearBtn.setTextColor(GRAY);
        clearBtn.setPadding(Math.round(10 * d), Math.round(5 * d), Math.round(10 * d), Math.round(5 * d));
        clearBtn.setBackground(shape(PANEL_ELEV, Math.round(8 * d), BORDER_STRONG, d));
        bar.addView(clearBtn);

        TextView loading = new TextView(activity);
        loading.setText("Загрузка установленных приложений…");
        loading.setTextSize(12);
        loading.setTextColor(GRAY);
        loading.setPadding(0, Math.round(8 * d), 0, Math.round(6 * d));
        root.addView(loading);

        ListView listView = new ListView(activity);
        listView.setBackground(shape(BG, Math.round(12 * d), BORDER, d));
        listView.setDivider(new ColorDrawable(BORDER));
        listView.setDividerHeight(Math.max(1, Math.round(d)));
        listView.setClipToOutline(true);
        LinearLayout.LayoutParams lvLp = new LinearLayout.LayoutParams(-1, Math.round(330 * d));
        lvLp.topMargin = Math.round(4 * d);
        root.addView(listView, lvLp);

        final List<AppItem> allApps = new ArrayList<>();
        final List<AppItem> filteredApps = new ArrayList<>();
        final Runnable updateCounter = () -> {
            int n = selected.size();
            counter.setText("Выбрано: " + n);
            counter.setTextColor(n > 0 ? GREEN : GRAY);
            clearBtn.setAlpha(n > 0 ? 1f : 0.45f);
            clearBtn.setEnabled(n > 0);
        };
        updateCounter.run();

        final BaseAdapter adapter = new BaseAdapter() {
            @Override public int getCount() { return filteredApps.size(); }
            @Override public AppItem getItem(int pos) { return filteredApps.get(pos); }
            @Override public long getItemId(int pos) { return pos; }
            @Override public View getView(int pos, View convertView, ViewGroup parent) {
                LinearLayout row;
                ImageView iconView;
                TextView titleView;
                TextView pkgView;
                CheckBox check;
                if (convertView instanceof LinearLayout) {
                    row = (LinearLayout) convertView;
                    iconView = (ImageView) row.getChildAt(0);
                    LinearLayout texts = (LinearLayout) row.getChildAt(1);
                    titleView = (TextView) texts.getChildAt(0);
                    pkgView = (TextView) texts.getChildAt(1);
                    check = (CheckBox) row.getChildAt(2);
                } else {
                    row = new LinearLayout(activity);
                    row.setOrientation(LinearLayout.HORIZONTAL);
                    row.setGravity(Gravity.CENTER_VERTICAL);
                    row.setPadding(Math.round(10 * d), Math.round(8 * d), Math.round(10 * d), Math.round(8 * d));

                    iconView = new ImageView(activity);
                    row.addView(iconView, new LinearLayout.LayoutParams(Math.round(32 * d), Math.round(32 * d)));

                    LinearLayout texts = new LinearLayout(activity);
                    texts.setOrientation(LinearLayout.VERTICAL);
                    LinearLayout.LayoutParams tLp = new LinearLayout.LayoutParams(0, -2, 1);
                    tLp.leftMargin = Math.round(10 * d);
                    tLp.rightMargin = Math.round(8 * d);
                    row.addView(texts, tLp);

                    titleView = new TextView(activity);
                    titleView.setTextSize(14);
                    titleView.setTextColor(WHITE);
                    titleView.setMaxLines(1);
                    titleView.setEllipsize(TextUtils.TruncateAt.END);
                    texts.addView(titleView);

                    pkgView = new TextView(activity);
                    pkgView.setTextSize(11);
                    pkgView.setTextColor(GRAY);
                    pkgView.setTypeface(Typeface.MONOSPACE);
                    pkgView.setMaxLines(1);
                    pkgView.setEllipsize(TextUtils.TruncateAt.END);
                    texts.addView(pkgView);

                    check = new CheckBox(activity);
                    check.setFocusable(false);
                    check.setClickable(false);
                    check.setFocusableInTouchMode(false);
                    check.setButtonTintList(new android.content.res.ColorStateList(
                        new int[][]{{android.R.attr.state_checked}, {}},
                        new int[]{GREEN, GRAY}));
                    row.addView(check);
                }
                AppItem item = filteredApps.get(pos);
                titleView.setText(item.label);
                pkgView.setText(item.system ? item.packageName + " · сис." : item.packageName);
                boolean isChecked = selected.contains(item.packageName);
                check.setChecked(isChecked);
                row.setBackgroundColor(isChecked ? PANEL_ELEV : Color.TRANSPARENT);
                Drawable cached = icons.get(item.packageName);
                if (cached == null) {
                    try {
                        cached = pm.getApplicationIcon(item.info);
                        if (cached != null) icons.put(item.packageName, cached);
                    } catch (Throwable ignored) {}
                }
                iconView.setImageDrawable(cached);
                return row;
            }
        };
        listView.setAdapter(adapter);

        final Runnable refilter = () -> {
            String query = search.getText().toString().trim().toLowerCase(Locale.ROOT);
            boolean showSystem = sysSwitch.isChecked();
            filteredApps.clear();
            for (AppItem item : allApps) {
                boolean isSelected = selected.contains(item.packageName);
                if (item.system && !showSystem && !isSelected) continue;
                if (!query.isEmpty() && !item.searchKey.contains(query)) continue;
                filteredApps.add(item);
            }
            if (!allApps.isEmpty()) {
                if (filteredApps.isEmpty()) {
                    loading.setText("Ничего не найдено");
                    loading.setVisibility(View.VISIBLE);
                } else {
                    loading.setVisibility(View.GONE);
                }
            }
            adapter.notifyDataSetChanged();
        };

        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(Editable s) { refilter.run(); }
        });
        sysSwitch.setOnCheckedChangeListener((b, checked) -> refilter.run());
        listView.setOnItemClickListener((parent, view, position, id) -> {
            if (position < 0 || position >= filteredApps.size()) return;
            String pkg = filteredApps.get(position).packageName;
            if (selected.contains(pkg)) selected.remove(pkg);
            else selected.add(pkg);
            updateCounter.run();
            adapter.notifyDataSetChanged();
        });
        clearBtn.setOnClickListener(v -> {
            if (selected.isEmpty()) return;
            selected.clear();
            updateCounter.run();
            refilter.run();
        });

        AlertDialog dialog = new AlertDialog.Builder(activity)
            .setTitle("Исключения приложений")
            .setView(root)
            .setPositiveButton("Сохранить", (dlg, which) -> {
                save(activity, selected);
                if (onSaved != null && !selected.equals(before)) {
                    onSaved.run();
                }
            })
            .setNegativeButton("Отмена", null)
            .create();
        dialog.setOnShowListener(d1 -> {
            Button pos = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            Button neg = dialog.getButton(AlertDialog.BUTTON_NEGATIVE);
            if (pos != null) pos.setTextColor(WHITE);
            if (neg != null) neg.setTextColor(GRAY);
        });
        dialog.show();

        final Handler ui = new Handler(Looper.getMainLooper());
        final String selfPkg = activity.getPackageName();
        final ExecutorService exec = Executors.newSingleThreadExecutor();
        exec.execute(() -> {
            List<AppItem> loaded = new ArrayList<>();
            HashSet<String> seen = new HashSet<>();
            try {
                List<ApplicationInfo> installed = pm.getInstalledApplications(0);
                for (ApplicationInfo ai : installed) {
                    if (ai == null || ai.packageName == null) continue;
                    String pkg = ai.packageName;
                    if (pkg.equals(selfPkg) || !VALID_PACKAGE.matcher(pkg).matches() || !seen.add(pkg)) continue;
                    CharSequence cs = pm.getApplicationLabel(ai);
                    String label = cs == null ? pkg : cs.toString().trim();
                    if (label.isEmpty()) label = pkg;
                    boolean hasLauncher = pm.getLaunchIntentForPackage(pkg) != null;
                    boolean isSystem = ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) && !hasLauncher;
                    loaded.add(new AppItem(ai, pkg, label, isSystem));
                }
                // Preserve any previously saved package even if query was restricted by OEM
                for (String pkg : before) {
                    if (seen.add(pkg)) {
                        loaded.add(new AppItem(new ApplicationInfo(), pkg, pkg, false));
                    }
                }
                loaded.sort((a, b) -> {
                    boolean aSel = before.contains(a.packageName);
                    boolean bSel = before.contains(b.packageName);
                    if (aSel != bSel) return aSel ? -1 : 1;
                    int cmp = a.label.compareToIgnoreCase(b.label);
                    return cmp != 0 ? cmp : a.packageName.compareToIgnoreCase(b.packageName);
                });
            } finally {
                exec.shutdown();
            }
            ui.post(() -> {
                if (activity.isFinishing() || activity.isDestroyed() || !dialog.isShowing()) return;
                allApps.clear();
                allApps.addAll(loaded);
                if (allApps.isEmpty()) {
                    loading.setText("Не удалось получить список приложений");
                    loading.setVisibility(View.VISIBLE);
                } else {
                    loading.setVisibility(View.GONE);
                }
                refilter.run();
            });
        });
        return dialog;
    }

    private static GradientDrawable shape(int fill, int radius, int stroke, float density) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(fill);
        g.setCornerRadius(radius);
        g.setStroke(Math.max(1, Math.round(density)), stroke);
        return g;
    }
}
