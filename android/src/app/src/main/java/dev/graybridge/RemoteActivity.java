package dev.graybridge;

import android.app.*;
import android.content.*;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.*;
import android.text.InputType;
import android.text.TextUtils;
import android.view.*;
import android.widget.*;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;

public class RemoteActivity extends Activity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final ExecutorService WORK = Executors.newSingleThreadExecutor();
    private static final int BG = Color.rgb(11, 11, 13);
    private static final int PANEL = Color.rgb(20, 20, 24);
    private static final int PANEL_ELEV = Color.rgb(28, 28, 34);
    private static final int FG = Color.rgb(242, 242, 245);
    private static final int MUTED = Color.rgb(142, 142, 152);
    private static final int DIM = Color.rgb(92, 92, 102);
    private static final int BORDER = Color.rgb(40, 40, 48);
    private static final int BORDER_STRONG = Color.rgb(60, 60, 72);
    private static final int GREEN = Color.rgb(52, 211, 153);
    private static final int AMBER = Color.rgb(251, 191, 36);
    private static final int RED = Color.rgb(248, 113, 113);

    private LinearLayout page;
    private boolean working;
    private String message = "";
    private byte[] identity;
    private String pendingTitle, pendingAction;

    private String mode() { return Settings.prefs(this).getString("remote_mode", "server"); }

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(BG);
        scroll.setFillViewport(true);
        scroll.setOnApplyWindowInsetsListener((v, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
                v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            } else {
                v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                    insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            }
            return insets;
        });
        page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(18), dp(14), dp(18), dp(20));
        scroll.addView(page);
        setContentView(scroll);
        draw();
    }

    @Override protected void onStart() { super.onStart(); AppUpdates.check(this, false); }
    @Override protected void onResume() {
        super.onResume();
        AppUpdates.resume(this);
        Settings.prefs(this).registerOnSharedPreferenceChangeListener(this);
        draw();
    }
    @Override protected void onPause() {
        Settings.prefs(this).unregisterOnSharedPreferenceChangeListener(this);
        super.onPause();
    }
    @Override public void onSharedPreferenceChanged(SharedPreferences p, String key) {
        if (key.equals("remote_state") || key.equals("remote_error")) runOnUiThread(this::draw);
    }

    private int dp(int n) { return Math.round(getResources().getDisplayMetrics().density * n); }

    private GradientDrawable shape(int fill, int radius, int stroke) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(fill);
        d.setCornerRadius(radius);
        d.setStroke(dp(1), stroke);
        return d;
    }

    private TextView label(String s, int size, int color) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(size);
        t.setTextColor(color);
        return t;
    }

    private void actionCard(LinearLayout container, String title, String subtitle, Runnable click, boolean enabled) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(dp(16), dp(13), dp(16), dp(13));
        row.setBackground(shape(PANEL, dp(14), BORDER));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(8);
        row.setLayoutParams(lp);

        TextView a = label(title, 14, FG);
        a.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        row.addView(a);
        if (subtitle != null && !subtitle.isEmpty()) {
            TextView b = label(subtitle, 11, MUTED);
            LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(-1, -2);
            bp.topMargin = dp(3);
            row.addView(b, bp);
        }
        row.setAlpha(enabled ? 1f : .45f);
        row.setEnabled(enabled);
        if (enabled) row.setOnClickListener(v -> click.run());
        container.addView(row);
    }

    private void switchTab(int targetIdx) {
        if (working) return;
        if (targetIdx == 0) {
            if (RemoteVpnService.busy(this)) RemoteVpnService.stop(this);
            Settings.prefs(this).edit().putBoolean("remote_home", false).apply();
            startActivity(new Intent(this, MainActivity.class));
            finish();
            return;
        }
        String nextMode = targetIdx == 1 ? "server" : "subscriptions";
        if (nextMode.equals(mode())) return;
        if (RemoteVpnService.busy(this)) RemoteVpnService.stop(this);
        Settings.prefs(this).edit().putString("remote_mode", nextMode).apply();
        message = "";
        draw();
    }

    private void draw() {
        page.removeAllViews();
        boolean server = mode().equals("server");
        String state = RemoteVpnService.status(this);
        boolean busy = RemoteVpnService.busy(this);
        boolean editable = !busy && !working && !Settings.busy(this);

        // 1. Header
        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        TextView brand = label("SorryRKN", 21, FG);
        brand.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        header.addView(brand);
        TextView ver = label("v" + BuildConfig.VERSION_NAME, 11, MUTED);
        ver.setTypeface(Typeface.MONOSPACE);
        ver.setPadding(dp(7), dp(2), dp(7), dp(2));
        ver.setBackground(shape(PANEL_ELEV, dp(6), BORDER));
        LinearLayout.LayoutParams vLp = new LinearLayout.LayoutParams(-2, -2);
        vLp.leftMargin = dp(8);
        header.addView(ver, vLp);
        page.addView(header);

        // 2. Top 3-Segment Mode Bar
        LinearLayout modeBar = new LinearLayout(this);
        modeBar.setOrientation(LinearLayout.HORIZONTAL);
        modeBar.setPadding(dp(4), dp(4), dp(4), dp(4));
        modeBar.setBackground(shape(PANEL, dp(12), BORDER));
        LinearLayout.LayoutParams mbLp = new LinearLayout.LayoutParams(-1, -2);
        mbLp.topMargin = dp(12);
        page.addView(modeBar, mbLp);

        String[] modes = {"Локальный", "Свой сервер", "Подписки"};
        int activeIdx = server ? 1 : 2;
        for (int i = 0; i < modes.length; i++) {
            final int idx = i;
            boolean active = idx == activeIdx;
            TextView tab = label(modes[i], 12, active ? FG : MUTED);
            tab.setTypeface(Typeface.create(active ? "sans-serif-medium" : "sans-serif", Typeface.NORMAL));
            tab.setGravity(Gravity.CENTER);
            tab.setPadding(dp(6), dp(9), dp(6), dp(9));
            if (active) tab.setBackground(shape(PANEL_ELEV, dp(9), BORDER_STRONG));
            modeBar.addView(tab, new LinearLayout.LayoutParams(0, -2, 1));
            if (!active) tab.setOnClickListener(v -> switchTab(idx));
        }

        // 3. Tactical Hero Card
        int dotColor = switch (state) {
            case "on" -> GREEN;
            case "starting", "stopping" -> AMBER;
            case "error" -> RED;
            default -> DIM;
        };
        int heroStroke = switch (state) {
            case "on" -> Color.argb(110, 52, 211, 153);
            case "starting", "stopping" -> Color.argb(110, 251, 191, 36);
            case "error" -> Color.argb(120, 248, 113, 113);
            default -> BORDER;
        };
        LinearLayout hero = new LinearLayout(this);
        hero.setOrientation(LinearLayout.VERTICAL);
        hero.setPadding(dp(16), dp(16), dp(16), dp(16));
        hero.setBackground(shape(PANEL, dp(18), heroStroke));
        LinearLayout.LayoutParams heroLp = new LinearLayout.LayoutParams(-1, -2);
        heroLp.topMargin = dp(12);
        page.addView(hero, heroLp);

        LinearLayout statusRow = new LinearLayout(this);
        statusRow.setGravity(Gravity.CENTER_VERTICAL);
        View dot = new View(this);
        dot.setBackground(shape(dotColor, dp(5), dotColor));
        statusRow.addView(dot, new LinearLayout.LayoutParams(dp(8), dp(8)));

        String statusTitle = switch (state) {
            case "on" -> "Туннель включён";
            case "starting" -> "Подключение…";
            case "stopping" -> "Отключение…";
            case "error" -> "Ошибка туннеля";
            default -> "Выключено";
        };
        TextView current = label(statusTitle, 17, FG);
        current.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        LinearLayout.LayoutParams stLp = new LinearLayout.LayoutParams(-2, -2);
        stLp.leftMargin = dp(8);
        statusRow.addView(current, stLp);
        hero.addView(statusRow);

        try {
            if (server) {
                JSONObject profile = RemoteVault.read(this, "server");
                String hostLabel = profile.optString("host", "Сервер ещё не настроен");
                String protoLabel = profile.has("https")
                    ? (NaiveEngine.relay(profile.getString("https")) != null
                        ? "HTTPS туннель · TCP и UDP"
                        : "Старый HTTPS-профиль · обновите через SSH")
                    : "Настройте HTTPS или VLESS / REALITY по SSH";
                TextView sub1 = label(hostLabel, 13, FG);
                sub1.setPadding(0, dp(6), 0, 0);
                hero.addView(sub1);
                TextView sub2 = label(protoLabel, 12, MUTED);
                sub2.setPadding(0, dp(2), 0, dp(12));
                hero.addView(sub2);

                boolean canToggle = !working && !Settings.busy(this)
                    && (state.equals("on") || state.equals("starting") || (!busy && profile.has("https")));
                String btnTitle = state.equals("starting") ? "Отменить подключение" : (busy ? "Отключить" : "Подключить");
                primaryButton(hero, btnTitle, this::toggle, canToggle, state.equals("on"));

                actionCard(page, "Управление сервером по SSH  ›",
                    "Автонастройка HTTPS, VLESS / REALITY и локального SOCKS5", this::serverMenu, editable);
                if (SshForward.port() > 0) {
                    actionCard(page, "Отключить локальный SOCKS5",
                        "127.0.0.1:" + SshForward.port(),
                        () -> { SshForward.stop(this); message = "SSH-переадресация отключена"; draw(); }, !working);
                }
            } else {
                JSONObject book = RemoteSubscriptions.library(this);
                JSONArray groups = book.getJSONArray("groups");
                JSONObject group = groups.length() > 0 ? RemoteSubscriptions.selected(book) : null;
                String subTitle = "Добавьте ссылку подписки или узла VLESS / Trojan / Shadowsocks";
                if (group != null) {
                    String nodeName = group.getJSONArray("nodes").getJSONObject(group.optInt("index")).getString("name");
                    subTitle = group.getString("name") + " · " + nodeName;
                }
                TextView sub1 = label(subTitle, 13, group != null ? FG : MUTED);
                sub1.setMaxLines(2);
                sub1.setEllipsize(TextUtils.TruncateAt.END);
                sub1.setPadding(0, dp(6), 0, dp(12));
                hero.addView(sub1);

                boolean canToggle = !working && !Settings.busy(this)
                    && (state.equals("on") || state.equals("starting") || (!busy && group != null));
                String btnTitle = state.equals("starting") ? "Отменить подключение" : (busy ? "Отключить" : "Подключить");
                primaryButton(hero, btnTitle, this::toggle, canToggle, state.equals("on"));

                actionCard(page, "Добавить подписку или узел  ›",
                    "HTTPS-подписка или прямая ссылка vless://, trojan://, ss://", this::addSubscription, editable);
                if (group != null) {
                    actionCard(page, "Выбрать подписку и узел  ›",
                        "Переключение активного узла в библиотеке", this::chooseGroup, editable);
                    if (!group.optString("url").isEmpty()) {
                        actionCard(page, "Обновить список узлов",
                            group.optString("name"), () -> loadSubscription(group.optString("url"), true), editable);
                    }
                    actionCard(page, "Удалить выбранную подписку",
                        null, this::removeGroup, editable);
                }
            }
        } catch (Exception e) {
            TextView err = label("Не удалось прочитать защищённый профиль.", 13, RED);
            err.setPadding(0, dp(8), 0, 0);
            hero.addView(err);
        }

        String noteText = working ? "Выполняется операция…"
            : (message.isEmpty() ? Settings.prefs(this).getString("remote_error", "") : message);
        if (!noteText.isEmpty()) {
            TextView note = label(noteText, 12, state.equals("error") ? RED : MUTED);
            note.setPadding(dp(4), dp(14), dp(4), 0);
            page.addView(note);
        }
    }

    private void primaryButton(LinearLayout parent, String title, Runnable click, boolean enabled, boolean active) {
        TextView btn = label(title, 14, active ? BG : FG);
        btn.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        btn.setGravity(Gravity.CENTER);
        btn.setPadding(dp(16), dp(12), dp(16), dp(12));
        btn.setBackground(shape(active ? FG : PANEL_ELEV, dp(12), active ? FG : BORDER_STRONG));
        btn.setAlpha(enabled ? 1f : .4f);
        btn.setEnabled(enabled);
        if (enabled) btn.setOnClickListener(v -> click.run());
        parent.addView(btn, new LinearLayout.LayoutParams(-1, -2));
    }

    private void toggle() {
        String st = RemoteVpnService.status(this);
        if (st.equals("on") || st.equals("starting")) {
            RemoteVpnService.stop(this);
            return;
        }
        Intent consent = VpnService.prepare(this);
        if (consent != null) startActivityForResult(consent, 42);
        else startTunnel();
    }

    private void startTunnel() {
        if (Settings.busy(this) || RemoteVpnService.busy(this)) return;
        RemoteVpnService.start(this);
    }

    @Override protected void onActivityResult(int code, int result, Intent data) {
        super.onActivityResult(code, result, data);
        if (code == 42 && result == RESULT_OK) startTunnel();
        if (code == 44 && result == RESULT_OK && data != null && data.getData() != null) {
            try (InputStream stream = getContentResolver().openInputStream(data.getData().normalizeScheme());
                 ByteArrayOutputStream buf = new ByteArrayOutputStream()) {
                if (stream == null) throw new IOException();
                byte[] bytes = new byte[4096];
                int n;
                while ((n = stream.read(bytes)) != -1) {
                    if (buf.size() + n > 131072) throw new IOException();
                    buf.write(bytes, 0, n);
                }
                byte[] key = buf.toByteArray();
                if (!new String(key, 0, Math.min(key.length, 100), StandardCharsets.US_ASCII).contains("PRIVATE KEY-----")) {
                    throw new IOException();
                }
                identity = key;
                if (pendingAction != null) sshForm(pendingTitle, pendingAction);
            } catch (Exception e) {
                message = "Не удалось прочитать SSH-ключ";
                draw();
            }
        }
    }

    private void run(Callable<String> work) {
        if (working) return;
        working = true;
        message = "";
        draw();
        WORK.execute(() -> {
            String result;
            try {
                result = work.call();
            } catch (Exception e) {
                result = e instanceof IOException && e.getMessage() != null
                    ? e.getMessage()
                    : "Не удалось выполнить операцию. Проверьте формат и подключение.";
            }
            String value = result;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                working = false;
                message = value;
                draw();
            });
        });
    }

    private void addSubscription() {
        EditText input = new EditText(this);
        input.setHint("HTTPS-ссылка подписки или ссылка узла");
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        new AlertDialog.Builder(this).setTitle("Новая подписка").setView(input)
            .setPositiveButton("Добавить", (d, w) -> loadSubscription(input.getText().toString(), false))
            .setNegativeButton("Отмена", null).show();
    }

    private void loadSubscription(String source, boolean refresh) {
        run(() -> RemoteSubscriptions.update(this, source, refresh));
    }

    private void chooseGroup() {
        try {
            JSONObject book = RemoteSubscriptions.library(this);
            JSONArray groups = book.getJSONArray("groups");
            String[] titles = new String[groups.length()];
            for (int i = 0; i < titles.length; i++) titles[i] = groups.getJSONObject(i).getString("name");
            new AlertDialog.Builder(this).setTitle("Подписки").setItems(titles, (d, index) -> {
                try {
                    JSONObject group = groups.getJSONObject(index);
                    JSONArray nodes = group.getJSONArray("nodes");
                    String[] names = new String[nodes.length()];
                    for (int i = 0; i < names.length; i++) names[i] = nodes.getJSONObject(i).getString("name");
                    new AlertDialog.Builder(this).setTitle(titles[index])
                        .setSingleChoiceItems(names, group.optInt("index"), (dialog, n) -> {
                            dialog.dismiss();
                            run(() -> {
                                group.put("index", n);
                                book.put("selected", index);
                                RemoteVault.write(this, "subscriptions", book);
                                return "";
                            });
                        }).setNegativeButton("Отмена", null).show();
                } catch (Exception e) {
                    message = "Не удалось прочитать узлы";
                    draw();
                }
            }).show();
        } catch (Exception e) {
            message = "Не удалось прочитать библиотеку";
            draw();
        }
    }

    private void removeGroup() {
        new AlertDialog.Builder(this).setTitle("Удалить выбранную подписку?")
            .setPositiveButton("Удалить", (d, w) -> run(() -> {
                JSONObject book = RemoteSubscriptions.library(this);
                book.getJSONArray("groups").remove(book.optInt("selected"));
                book.put("selected", 0);
                RemoteVault.write(this, "subscriptions", book);
                return "";
            })).setNegativeButton("Отмена", null).show();
    }

    private void serverMenu() {
        String[] titles = {
            "Настроить HTTPS", "Состояние HTTPS и SOCKS5", "Запустить HTTPS", "Остановить HTTPS",
            "Включить SOCKS5 через SSH", "Остановить SOCKS5", "Настроить VLESS / REALITY",
            "Получить узел REALITY", "Состояние REALITY", "Остановить REALITY", "Показать данные SOCKS5"
        };
        String[] actions = {
            "https-on", "https-status", "https-start", "https-off",
            "install-socks", "stop-socks", "reality-on", "reality-profile", "reality-status", "reality-off"
        };
        new AlertDialog.Builder(this).setTitle("Управление сервером").setItems(titles, (d, i) -> {
            if (i == actions.length) {
                try {
                    String socks = SshForward.port() > 0
                        ? "127.0.0.1:" + SshForward.port() + "\n" + RemoteVault.read(this, "server").optString("socks")
                        : "Подключите SOCKS5 через SSH.";
                    new AlertDialog.Builder(this).setTitle("Локальный SOCKS5").setMessage(socks)
                        .setPositiveButton("Закрыть", null).show();
                } catch (Exception e) {
                    message = "Не удалось прочитать данные SOCKS5";
                    draw();
                }
            } else {
                sshForm(titles[i], actions[i]);
            }
        }).show();
    }

    private EditText field(LinearLayout form, String hint, String value, int type) {
        EditText input = new EditText(this);
        input.setSingleLine();
        input.setHint(hint);
        input.setText(value);
        input.setInputType(type);
        input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        form.addView(input);
        return input;
    }

    private void sshForm(String title, String action) {
        try {
            JSONObject previous = RemoteVault.read(this, "server");
            LinearLayout form = new LinearLayout(this);
            form.setPadding(dp(18), dp(8), dp(18), 0);
            form.setOrientation(LinearLayout.VERTICAL);
            TextView help = new TextView(this);
            help.setText("Debian / Ubuntu, root либо sudo без пароля. "
                + (identity == null ? "Вход по паролю." : "Выбран SSH-ключ."));
            form.addView(help);
            EditText host = field(form, "Адрес сервера", previous.optString("host"), InputType.TYPE_CLASS_TEXT);
            EditText port = field(form, "Порт", String.valueOf(previous.optInt("port", 22)), InputType.TYPE_CLASS_NUMBER);
            EditText user = field(form, "Пользователь", previous.optString("user", "root"), InputType.TYPE_CLASS_TEXT);
            EditText pass = field(form, identity == null ? "Пароль SSH" : "Пароль ключа (если есть)", "",
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            new AlertDialog.Builder(this).setTitle(title).setView(form)
                .setPositiveButton("Выполнить", (d, w) -> {
                    try {
                        String h = ServerSSH.host(host.getText().toString());
                        int p = Integer.parseInt(port.getText().toString());
                        boolean same = h.equals(previous.optString("host")) && p == previous.optInt("port");
                        JSONObject profile = same ? previous : new JSONObject();
                        profile.put("host", h).put("port", p).put("user", user.getText().toString());
                        ssh(profile, pass.getText().toString(), action);
                    } catch (Exception e) {
                        message = "Проверьте адрес и порт.";
                        draw();
                    }
                })
                .setNegativeButton("Отмена", null)
                .setNeutralButton(identity == null ? "SSH-ключ" : "По паролю", (d, w) -> {
                    if (identity != null) {
                        java.util.Arrays.fill(identity, (byte) 0);
                        identity = null;
                        sshForm(title, action);
                        return;
                    }
                    pendingAction = action;
                    pendingTitle = title;
                    startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT)
                        .addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), 44);
                }).show();
        } catch (Exception e) {
            message = "Не удалось прочитать сервер";
            draw();
        }
    }

    private void ssh(JSONObject profile, String password, String action) {
        run(() -> {
            try {
                String record = ServerSSH.run(this, profile, password, action, identity);
                String result = ServerSSH.apply(profile, record);
                if (record.startsWith("SRKN1\tREALITY\t")) {
                    RemoteSubscriptions.update(this, profile.getString("reality"), false);
                }
                RemoteVault.write(this, "server", profile);
                return result;
            } catch (ServerSSH.Untrusted first) {
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    new AlertDialog.Builder(this).setTitle("Ключ SSH сервера")
                        .setMessage(profile.optString("host") + "\n" + first.fingerprint
                            + "\n\nСверьте отпечаток с консолью VPS. После подтверждения ключ будет закреплён.")
                        .setNegativeButton("Отмена", null)
                        .setPositiveButton("Ключ совпадает", (d, w) -> {
                            try {
                                profile.put("pin", first.fingerprint);
                                ssh(profile, password, action);
                            } catch (Exception e) {
                                message = "Не удалось сохранить отпечаток";
                                draw();
                            }
                        }).show();
                });
                return "";
            }
        });
    }
}
