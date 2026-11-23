package dev.graybridge;

import android.app.*;
import android.content.*;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.*;
import android.text.InputType;
import android.text.TextUtils;
import android.view.*;
import android.widget.*;
import org.json.*;
import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
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

    private static final class ProtoSpec {
        final String key, title, badge, desc, onAct, offAct, purgeAct;
        ProtoSpec(String key, String title, String badge, String desc, String onAct, String offAct, String purgeAct) {
            this.key = key;
            this.title = title;
            this.badge = badge;
            this.desc = desc;
            this.onAct = onAct;
            this.offAct = offAct;
            this.purgeAct = purgeAct;
        }
    }

    private static final ProtoSpec[] PROTOCOLS = {
        new ProtoSpec("mirage", "SRKN-Mirage v1 («Мираж»)", "Анти-DPI · TCP 2096",
            "Уникальный транспорт: uTLS Chrome + скрытый HTTP-стук + обфускация", "mirage-on", "mirage-off", "mirage-purge"),
        new ProtoSpec("reality", "VLESS + REALITY Vision", "TCP 8443",
            "Маскировка под легитимный TLS 1.3 без собственного домена", "reality-on", "reality-off", "reality-purge"),
        new ProtoSpec("https", "HTTPS / NaïveProxy", "TCP 443 · TCP+UDP",
            "Трафик браузера Chrome HTTP/2 с поддержкой UDP-релея", "https-on", "https-off", "https-purge"),
        new ProtoSpec("hy2", "Hysteria2 + Salamander", "UDP 8443 · QUIC",
            "Скоростной QUIC с маскировкой пакетов и PIN-сертификатом", "hy2-on", "hy2-off", "hy2-purge"),
        new ProtoSpec("grpc", "VLESS + REALITY gRPC", "TCP 2053",
            "Мультиплексированный HTTP/2 через REALITY при блоках Vision", "grpc-on", "grpc-off", "grpc-purge"),
        new ProtoSpec("ss2022", "Shadowsocks 2022", "TCP+UDP 2083",
            "Быстрый AEAD-шифр 2022-blake3-aes-256-gcm", "ss2022-on", "ss2022-off", "ss2022-purge"),
    };

    private LinearLayout page;
    private boolean working;
    private String message = "";
    private byte[] pickedIdentity;
    private Runnable onIdentityPicked;

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
        page.setPadding(dp(18), dp(14), dp(18), dp(24));
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

    private TextView pillButton(String title, int fill, int border, int fg, Runnable click, boolean enabled) {
        TextView b = label(title, 11, fg);
        b.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        b.setPadding(dp(10), dp(6), dp(10), dp(6));
        b.setBackground(shape(fill, dp(8), border));
        b.setAlpha(enabled ? 1f : .42f);
        b.setEnabled(enabled);
        if (enabled && click != null) b.setOnClickListener(v -> click.run());
        return b;
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

    // ---- Multi-server Encrypted Store ----

    private JSONObject loadFleet() throws Exception {
        JSONObject fleet = RemoteVault.read(this, "servers_v2");
        JSONArray list = fleet.optJSONArray("servers");
        if (list == null) {
            list = new JSONArray();
            JSONObject legacy = RemoteVault.read(this, "server");
            if (!legacy.optString("host", "").isEmpty()) {
                JSONObject item = new JSONObject(legacy.toString());
                String id = item.optString("id", UUID.randomUUID().toString().replace("-", ""));
                item.put("id", id);
                if (item.optString("name", "").isEmpty()) item.put("name", item.optString("host"));
                if (item.optString("active_uri", "").isEmpty() && item.has("https")) {
                    item.put("active_proto", "https");
                    item.put("active_uri", item.getString("https"));
                }
                list.put(item);
                fleet.put("active_id", id);
            }
            fleet.put("servers", list);
            RemoteVault.write(this, "servers_v2", fleet);
        }
        if (fleet.optString("active_id", "").isEmpty() && list.length() > 0) {
            fleet.put("active_id", list.getJSONObject(0).getString("id"));
        }
        return fleet;
    }

    private JSONObject activeServer(JSONObject fleet) {
        String activeId = fleet.optString("active_id", "");
        JSONArray arr = fleet.optJSONArray("servers");
        if (arr == null || arr.length() == 0) return null;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject s = arr.optJSONObject(i);
            if (s != null && activeId.equals(s.optString("id"))) return s;
        }
        return arr.optJSONObject(0);
    }

    private void saveFleet(JSONObject fleet) throws Exception {
        RemoteVault.write(this, "servers_v2", fleet);
        JSONObject active = activeServer(fleet);
        RemoteVault.write(this, "server", active == null ? new JSONObject() : new JSONObject(active.toString()));
    }

    private static String pickNextActiveUri(JSONObject srv) {
        for (ProtoSpec spec : PROTOCOLS) {
            String uri = srv.optString(spec.key, "");
            if (!uri.isEmpty()) {
                try { srv.put("active_proto", spec.key); } catch (JSONException ignored) {}
                return uri;
            }
        }
        try { srv.remove("active_proto"); } catch (JSONException ignored) {}
        return "";
    }

    private void draw() {
        page.removeAllViews();
        boolean serverTab = mode().equals("server");
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

        // 2. Mode Bar
        LinearLayout modeBar = new LinearLayout(this);
        modeBar.setOrientation(LinearLayout.HORIZONTAL);
        modeBar.setPadding(dp(4), dp(4), dp(4), dp(4));
        modeBar.setBackground(shape(PANEL, dp(12), BORDER));
        LinearLayout.LayoutParams mbLp = new LinearLayout.LayoutParams(-1, -2);
        mbLp.topMargin = dp(12);
        page.addView(modeBar, mbLp);

        String[] modes = {"Локальный", "Свой сервер", "Подписки"};
        int activeIdx = serverTab ? 1 : 2;
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

        // 3. Hero Card
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
        hero.setPadding(dp(16), dp(15), dp(16), dp(15));
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
            if (serverTab) {
                drawServerFleetTab(hero, state, busy, editable);
            } else {
                drawSubscriptionsTab(hero, state, busy, editable);
            }
        } catch (Exception e) {
            TextView err = label("Не удалось прочитать защищённое хранилище.", 13, RED);
            err.setPadding(0, dp(8), 0, 0);
            hero.addView(err);
        }

        String noteText = working ? "Выполняется SSH / настройка сервера…"
            : (message.isEmpty() ? Settings.prefs(this).getString("remote_error", "") : message);
        if (!noteText.isEmpty()) {
            TextView note = label(noteText, 12, state.equals("error") ? RED : MUTED);
            note.setPadding(dp(4), dp(12), dp(4), 0);
            page.addView(note);
        }
    }

    private void drawServerFleetTab(LinearLayout hero, String state, boolean busy, boolean editable) throws Exception {
        JSONObject fleet = loadFleet();
        JSONArray servers = fleet.getJSONArray("servers");
        JSONObject selected = activeServer(fleet);

        String hostLabel = selected == null
            ? "Сервер не добавлен"
            : selected.optString("name", selected.optString("host")) + " · " + selected.optString("host");
        String activeProto = selected == null ? "" : selected.optString("active_proto", "");
        String protoLabel = "Добавьте VPS и установите протокол (рекомендуем SRKN-Mirage v1)";
        if (selected != null && !selected.optString("active_uri", "").isEmpty()) {
            ProtoSpec sp = findProto(activeProto);
            protoLabel = sp != null ? (sp.title + " · готов к подключению") : "Активный профиль готов";
        }
        TextView sub1 = label(hostLabel, 13, selected != null ? FG : MUTED);
        sub1.setPadding(0, dp(6), 0, 0);
        hero.addView(sub1);
        TextView sub2 = label(protoLabel, 12, MUTED);
        sub2.setPadding(0, dp(2), 0, dp(12));
        hero.addView(sub2);

        boolean canConnect = selected != null && (!selected.optString("active_uri", "").isEmpty() || selected.has("https"));
        boolean canToggle = !working && !Settings.busy(this)
            && (state.equals("on") || state.equals("starting") || (!busy && canConnect));
        String btnTitle = state.equals("starting") ? "Отменить подключение" : (busy ? "Отключить" : "Подключить");
        primaryButton(hero, btnTitle, this::toggle, canToggle, state.equals("on"));

        // Server switcher pills row
        LinearLayout fleetHeader = new LinearLayout(this);
        fleetHeader.setOrientation(LinearLayout.HORIZONTAL);
        fleetHeader.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams fhLp = new LinearLayout.LayoutParams(-1, -2);
        fhLp.topMargin = dp(14);
        page.addView(fleetHeader, fhLp);

        TextView srvTitle = label("Мои серверы (" + servers.length() + ")", 13, FG);
        srvTitle.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        fleetHeader.addView(srvTitle, new LinearLayout.LayoutParams(0, -2, 1));

        if (selected != null) {
            TextView editBtn = pillButton("Изменить", PANEL_ELEV, BORDER_STRONG, FG, () -> openServerEditor(selected), editable);
            LinearLayout.LayoutParams eLp = new LinearLayout.LayoutParams(-2, -2);
            eLp.rightMargin = dp(6);
            fleetHeader.addView(editBtn, eLp);
            TextView delBtn = pillButton("Удалить", PANEL, Color.argb(90, 248, 113, 113), RED, () -> deleteServer(selected), editable);
            fleetHeader.addView(delBtn);
        }

        HorizontalScrollView hsv = new HorizontalScrollView(this);
        hsv.setHorizontalScrollBarEnabled(false);
        LinearLayout.LayoutParams hsvLp = new LinearLayout.LayoutParams(-1, -2);
        hsvLp.topMargin = dp(8);
        page.addView(hsv, hsvLp);

        LinearLayout chipRow = new LinearLayout(this);
        chipRow.setOrientation(LinearLayout.HORIZONTAL);
        hsv.addView(chipRow);

        for (int i = 0; i < servers.length(); i++) {
            JSONObject srv = servers.getJSONObject(i);
            String id = srv.getString("id");
            boolean isActive = selected != null && id.equals(selected.optString("id"));
            TextView chip = pillButton(
                srv.optString("name", srv.optString("host")),
                isActive ? PANEL_ELEV : PANEL,
                isActive ? GREEN : BORDER_STRONG,
                isActive ? GREEN : FG,
                () -> {
                    if (isActive || !editable) return;
                    run(() -> {
                        JSONObject f = loadFleet();
                        f.put("active_id", id);
                        saveFleet(f);
                        return "Выбран сервер: " + srv.optString("name", srv.optString("host"));
                    });
                },
                editable);
            LinearLayout.LayoutParams cLp = new LinearLayout.LayoutParams(-2, -2);
            cLp.rightMargin = dp(8);
            chipRow.addView(chip, cLp);
        }
        TextView addChip = pillButton("+ Добавить VPS", PANEL_ELEV, BORDER_STRONG, FG, () -> openServerEditor(null), editable);
        chipRow.addView(addChip);

        if (selected == null) {
            actionCard(page, "Добавить первый VPS-сервер  ›",
                "Linux Debian / Ubuntu · вход по паролю или SSH-ключу", () -> openServerEditor(null), editable);
            return;
        }

        // Fleet toolbar (refresh status + purge all)
        LinearLayout tools = new LinearLayout(this);
        tools.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams tLp = new LinearLayout.LayoutParams(-1, -2);
        tLp.topMargin = dp(10);
        page.addView(tools, tLp);

        TextView checkAllBtn = pillButton("Проверить службы", PANEL, BORDER_STRONG, FG,
            () -> runServerAction(selected, "fleet-status", null), editable);
        checkAllBtn.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams caLp = new LinearLayout.LayoutParams(0, -2, 1);
        caLp.rightMargin = dp(8);
        tools.addView(checkAllBtn, caLp);

        TextView purgeAllBtn = pillButton("Удалить всё с VPS", PANEL, Color.argb(110, 248, 113, 113), RED,
            () -> confirmAndRun("Полная очистка VPS",
                "Удалить ВСЕ службы SorryRKN, конфиги и правила брандмауэра с " + selected.optString("host") + "?",
                selected, "purge-all"),
            editable);
        purgeAllBtn.setGravity(Gravity.CENTER);
        tools.addView(purgeAllBtn, new LinearLayout.LayoutParams(0, -2, 1));

        // SOCKS5 Proxy Card
        drawSocksCard(selected, editable);

        // Modern VPN Protocols Section
        TextView pHead = label("VPN-протоколы на «" + selected.optString("name", selected.optString("host")) + "»", 13, FG);
        pHead.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        LinearLayout.LayoutParams phLp = new LinearLayout.LayoutParams(-1, -2);
        phLp.topMargin = dp(14);
        page.addView(pHead, phLp);

        JSONObject fleetMap = selected.optJSONObject("fleet");
        for (ProtoSpec spec : PROTOCOLS) {
            drawProtocolCard(selected, spec, fleetMap, editable);
        }
    }

    private void drawSocksCard(JSONObject selected, boolean editable) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(14), dp(12), dp(14), dp(12));
        card.setBackground(shape(PANEL, dp(14), BORDER));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(10);
        page.addView(card, lp);

        TextView title = label("SOCKS5-прокси на VPS", 14, FG);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        card.addView(title);

        boolean hasSshSocks = SshForward.port() > 0 && !selected.optString("socks", "").isEmpty();
        boolean hasPubSocks = !selected.optString("socks_pub", "").isEmpty();
        StringBuilder sb = new StringBuilder();
        if (hasSshSocks) sb.append("SSH-туннель: 127.0.0.1:").append(SshForward.port());
        else sb.append("SSH-туннель: выкл");
        if (hasPubSocks) sb.append(" · Публ.: ").append(selected.optString("host")).append(":10808");
        TextView st = label(sb.toString(), 11, MUTED);
        LinearLayout.LayoutParams stLp = new LinearLayout.LayoutParams(-1, -2);
        stLp.topMargin = dp(3);
        card.addView(st, stLp);

        LinearLayout row1 = new LinearLayout(this);
        row1.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams r1Lp = new LinearLayout.LayoutParams(-1, -2);
        r1Lp.topMargin = dp(9);
        card.addView(row1, r1Lp);

        TextView sshBtn = pillButton("SSH (127.0.0.1)", PANEL_ELEV, BORDER_STRONG, FG,
            () -> runServerAction(selected, "install-socks", null), editable);
        sshBtn.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams b1 = new LinearLayout.LayoutParams(0, -2, 1);
        b1.rightMargin = dp(6);
        row1.addView(sshBtn, b1);

        TextView pubBtn = pillButton("Публ. 10808", PANEL_ELEV, BORDER_STRONG, FG,
            () -> runServerAction(selected, "socks-pub-on", null), editable);
        pubBtn.setGravity(Gravity.CENTER);
        row1.addView(pubBtn, new LinearLayout.LayoutParams(0, -2, 1));

        LinearLayout row2 = new LinearLayout(this);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams r2Lp = new LinearLayout.LayoutParams(-1, -2);
        r2Lp.topMargin = dp(7);
        card.addView(row2, r2Lp);

        boolean anySocks = hasSshSocks || hasPubSocks;
        TextView copyBtn = pillButton("Копировать", PANEL_ELEV, BORDER, FG,
            () -> shareSocksTarget(selected, false), editable && anySocks);
        copyBtn.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams c1 = new LinearLayout.LayoutParams(0, -2, 1);
        c1.rightMargin = dp(6);
        row2.addView(copyBtn, c1);

        TextView tgBtn = pillButton("Telegram", PANEL_ELEV, BORDER, GREEN,
            () -> shareSocksTarget(selected, true), editable && anySocks);
        tgBtn.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams c2 = new LinearLayout.LayoutParams(0, -2, 1);
        c2.rightMargin = dp(6);
        row2.addView(tgBtn, c2);

        TextView delBtn = pillButton("Удалить", PANEL, Color.argb(90, 248, 113, 113), RED,
            () -> confirmAndRun("Удалить SOCKS5",
                "Остановить и удалить SSH SOCKS5 и публичный SOCKS5 (10808) на " + selected.optString("host") + "?",
                selected, "socks-purge-both"),
            editable);
        delBtn.setGravity(Gravity.CENTER);
        row2.addView(delBtn, new LinearLayout.LayoutParams(0, -2, 1));
    }

    private void drawProtocolCard(JSONObject selected, ProtoSpec spec, JSONObject fleetMap, boolean editable) {
        String uri = selected.optString(spec.key, "");
        boolean isSelected = spec.key.equals(selected.optString("active_proto", "")) && !uri.isEmpty();
        String svcState = fleetMap != null ? fleetMap.optString(spec.key, "") : "";
        if (svcState.isEmpty() && !uri.isEmpty()) svcState = "saved";

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(14), dp(12), dp(14), dp(12));
        card.setBackground(shape(PANEL, dp(14), isSelected ? GREEN : BORDER));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(8);
        page.addView(card, lp);

        LinearLayout top = new LinearLayout(this);
        top.setOrientation(LinearLayout.HORIZONTAL);
        top.setGravity(Gravity.CENTER_VERTICAL);
        card.addView(top);

        int dotCol = switch (svcState) {
            case "running" -> GREEN;
            case "stopped" -> AMBER;
            case "saved" -> FG;
            default -> DIM;
        };
        View dot = new View(this);
        dot.setBackground(shape(dotCol, dp(4), dotCol));
        LinearLayout.LayoutParams dLp = new LinearLayout.LayoutParams(dp(7), dp(7));
        dLp.rightMargin = dp(7);
        top.addView(dot, dLp);

        TextView title = label(spec.title, 13, FG);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        top.addView(title, new LinearLayout.LayoutParams(0, -2, 1));

        TextView badge = label(spec.badge, 10, isSelected ? GREEN : MUTED);
        badge.setTypeface(Typeface.MONOSPACE);
        top.addView(badge);

        TextView desc = label(spec.desc, 11, MUTED);
        LinearLayout.LayoutParams deLp = new LinearLayout.LayoutParams(-1, -2);
        deLp.topMargin = dp(4);
        card.addView(desc, deLp);

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams aLp = new LinearLayout.LayoutParams(-1, -2);
        aLp.topMargin = dp(8);
        card.addView(actions, aLp);

        String primaryLbl = uri.isEmpty() ? "Установить" : (isSelected ? "Выбран ✓" : "Выбрать");
        TextView installOrSelect = pillButton(primaryLbl,
            isSelected ? Color.argb(40, 52, 211, 153) : PANEL_ELEV,
            isSelected ? GREEN : BORDER_STRONG,
            isSelected ? GREEN : FG,
            () -> {
                if (uri.isEmpty()) {
                    runServerAction(selected, spec.onAct, spec.key);
                } else if (!isSelected) {
                    run(() -> {
                        JSONObject f = loadFleet();
                        JSONObject cur = activeServer(f);
                        if (cur != null) {
                            cur.put("active_proto", spec.key);
                            cur.put("active_uri", cur.getString(spec.key));
                            saveFleet(f);
                        }
                        return "Активный протокол: " + spec.title;
                    });
                } else {
                    runServerAction(selected, spec.onAct, spec.key);
                }
            },
            editable);
        LinearLayout.LayoutParams p1 = new LinearLayout.LayoutParams(-2, -2);
        p1.rightMargin = dp(6);
        actions.addView(installOrSelect, p1);

        if (!uri.isEmpty()) {
            TextView copyBtn = pillButton("Ссылка", PANEL_ELEV, BORDER, FG, () -> {
                copyText(uri);
                message = "Ссылка " + spec.title + " скопирована.";
                draw();
            }, editable);
            LinearLayout.LayoutParams p2 = new LinearLayout.LayoutParams(-2, -2);
            p2.rightMargin = dp(6);
            actions.addView(copyBtn, p2);

            TextView stopBtn = pillButton("Стоп", PANEL, BORDER, AMBER,
                () -> confirmAndRun("Остановить " + spec.title,
                    "Остановить службу " + spec.title + " на сервере?", selected, spec.offAct),
                editable);
            LinearLayout.LayoutParams p3 = new LinearLayout.LayoutParams(-2, -2);
            p3.rightMargin = dp(6);
            actions.addView(stopBtn, p3);
        }

        if (!uri.isEmpty() || "running".equals(svcState) || "stopped".equals(svcState)) {
            TextView purgeBtn = pillButton("Удалить", PANEL, Color.argb(90, 248, 113, 113), RED,
                () -> confirmAndRun("Удалить " + spec.title,
                    "Удалить " + spec.title + " (конфиг, сервис и правило порта) с VPS?", selected, spec.purgeAct),
                editable);
            actions.addView(purgeBtn);
        }
    }

    private void drawSubscriptionsTab(LinearLayout hero, String state, boolean busy, boolean editable) throws Exception {
        JSONObject book = RemoteSubscriptions.library(this);
        JSONArray groups = book.getJSONArray("groups");
        JSONObject group = groups.length() > 0 ? RemoteSubscriptions.selected(book) : null;
        String subTitle = "Добавьте подписку или ссылку mirage://, hy2://, vless://, trojan://, ss://";
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
            "HTTPS-подписка или ссылки mirage://, hy2://, vless://, trojan://, ss://", this::addSubscription, editable);
        if (group != null) {
            actionCard(page, "Выбрать подписку и узел  ›",
                "Переключение активного узла в библиотеке", this::chooseGroup, editable);
            if (!group.optString("url").isEmpty()) {
                actionCard(page, "Обновить список узлов",
                    group.optString("name"), () -> loadSubscription(group.optString("url"), true), editable);
            }
            actionCard(page, "Удалить выбранную подписку", null, this::removeGroup, editable);
        }
    }

    private static ProtoSpec findProto(String key) {
        for (ProtoSpec p : PROTOCOLS) if (p.key.equals(key)) return p;
        return null;
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

    private void copyText(String val) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("SorryRKN", val));
    }

    private static String urlEnc(String s) {
        try { return URLEncoder.encode(s, StandardCharsets.UTF_8.name()); }
        catch (Exception e) { return s; }
    }

    private void shareSocksTarget(JSONObject srv, boolean telegram) {
        java.util.ArrayList<String> labels = new java.util.ArrayList<>();
        java.util.ArrayList<String> values = new java.util.ArrayList<>();
        String host = srv.optString("host");

        if (SshForward.port() > 0 && !srv.optString("socks", "").isEmpty()) {
            String[] up = srv.optString("socks").split("\n", 2);
            if (up.length == 2) {
                labels.add("SSH-туннель (127.0.0.1:" + SshForward.port() + ")");
                values.add(telegram
                    ? "tg://socks?server=127.0.0.1&port=" + SshForward.port() + "&user=" + urlEnc(up[0]) + "&pass=" + urlEnc(up[1])
                    : "socks5://" + urlEnc(up[0]) + ":" + urlEnc(up[1]) + "@127.0.0.1:" + SshForward.port());
            }
        }
        if (!srv.optString("socks_pub", "").isEmpty()) {
            String[] p = srv.optString("socks_pub").split("\n", 3);
            if (p.length == 3) {
                String bracket = host.contains(":") ? ("[" + host + "]") : host;
                labels.add("Публичный SOCKS5 (" + host + ":" + p[0] + ")");
                values.add(telegram
                    ? "tg://socks?server=" + urlEnc(host) + "&port=" + p[0] + "&user=" + urlEnc(p[1]) + "&pass=" + urlEnc(p[2])
                    : "socks5://" + urlEnc(p[1]) + ":" + urlEnc(p[2]) + "@" + bracket + ":" + p[0]);
            }
        }
        if (values.isEmpty()) return;
        Runnable applyFirst = () -> deliverSocksValue(values.get(0), telegram);
        if (values.size() == 1) {
            applyFirst.run();
            return;
        }
        new AlertDialog.Builder(this)
            .setTitle(telegram ? "Открыть в Telegram" : "Копировать SOCKS5")
            .setItems(labels.toArray(new String[0]), (d, i) -> deliverSocksValue(values.get(i), telegram))
            .show();
    }

    private void deliverSocksValue(String val, boolean telegram) {
        if (telegram) {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(val)));
            } catch (ActivityNotFoundException e) {
                copyText(val);
                message = "Telegram не установлен; ссылка прокси скопирована.";
                draw();
            }
            return;
        }
        copyText(val);
        message = "Адрес SOCKS5 скопирован:\n" + val;
        draw();
    }

    private void openServerEditor(JSONObject existing) {
        boolean isNew = existing == null;
        LinearLayout form = new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(dp(18), dp(10), dp(18), 0);

        EditText nameIn = field(form, "Название (например, Германия #1)", isNew ? "" : existing.optString("name"), InputType.TYPE_CLASS_TEXT);
        EditText hostIn = field(form, "IP или домен VPS", isNew ? "" : existing.optString("host"), InputType.TYPE_CLASS_TEXT);
        EditText portIn = field(form, "Порт SSH", String.valueOf(isNew ? 22 : existing.optInt("port", 22)), InputType.TYPE_CLASS_NUMBER);
        EditText userIn = field(form, "Пользователь (root)", isNew ? "root" : existing.optString("user", "root"), InputType.TYPE_CLASS_TEXT);
        EditText passIn = field(form, "Пароль SSH / ключа (необязательно)", isNew ? "" : existing.optString("password"),
            InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);

        boolean hadKey = !isNew && !existing.optString("key_pem", "").isEmpty();
        CheckBox rememberKey = new CheckBox(this);
        rememberKey.setText(hadKey ? "SSH-ключ сохранён (снимите для входа по паролю)" : "Выбрать файл SSH-ключа позже при запуске");
        rememberKey.setChecked(hadKey);
        if (!hadKey) rememberKey.setVisibility(View.GONE);
        form.addView(rememberKey);

        AlertDialog.Builder b = new AlertDialog.Builder(this)
            .setTitle(isNew ? "Новый сервер" : "Параметры сервера")
            .setView(form)
            .setPositiveButton("Сохранить", (d, w) -> run(() -> {
                String h = ServerSSH.host(hostIn.getText().toString());
                int p = Integer.parseInt(portIn.getText().toString().trim());
                if (p < 1 || p > 65535) throw new IOException("Неверный порт SSH");
                String u = userIn.getText().toString().trim();
                if (u.isEmpty()) u = "root";
                String nm = nameIn.getText().toString().trim();
                if (nm.isEmpty()) nm = h;

                JSONObject fleet = loadFleet();
                JSONArray arr = fleet.getJSONArray("servers");
                JSONObject item = null;
                if (!isNew) {
                    String tid = existing.getString("id");
                    for (int i = 0; i < arr.length(); i++) {
                        if (tid.equals(arr.getJSONObject(i).optString("id"))) { item = arr.getJSONObject(i); break; }
                    }
                }
                if (item == null) {
                    item = new JSONObject();
                    item.put("id", UUID.randomUUID().toString().replace("-", ""));
                    arr.put(item);
                }
                if (!h.equals(item.optString("host")) || p != item.optInt("port")) {
                    item.remove("pin");
                }
                item.put("name", nm).put("host", h).put("port", p).put("user", u)
                    .put("password", passIn.getText().toString());
                if (!rememberKey.isChecked()) item.remove("key_pem");
                fleet.put("active_id", item.getString("id"));
                saveFleet(fleet);
                return "Сервер «" + nm + "» сохранён.";
            }))
            .setNegativeButton("Отмена", null);

        if (!isNew && !existing.optString("pin", "").isEmpty()) {
            b.setNeutralButton("Забыть SSH-ключ", (d, w) -> run(() -> {
                JSONObject fleet = loadFleet();
                JSONObject cur = activeServer(fleet);
                if (cur != null) { cur.remove("pin"); saveFleet(fleet); }
                return "Отпечаток SSH сброшен.";
            }));
        }
        b.show();
    }

    private void deleteServer(JSONObject srv) {
        new AlertDialog.Builder(this)
            .setTitle("Удалить сервер?")
            .setMessage("Удалить «" + srv.optString("name", srv.optString("host")) + "» из приложения?\n\nЧтобы удалить службы с самого VPS, сначала нажмите «Удалить всё с VPS».")
            .setPositiveButton("Удалить", (d, w) -> run(() -> {
                if (RemoteVpnService.busy(this)) RemoteVpnService.stop(this);
                SshForward.stop(this);
                JSONObject fleet = loadFleet();
                JSONArray arr = fleet.getJSONArray("servers");
                String targetId = srv.getString("id");
                for (int i = 0; i < arr.length(); i++) {
                    if (targetId.equals(arr.getJSONObject(i).optString("id"))) { arr.remove(i); break; }
                }
                fleet.put("active_id", arr.length() > 0 ? arr.getJSONObject(0).getString("id") : "");
                saveFleet(fleet);
                return "Сервер удалён из списка.";
            }))
            .setNegativeButton("Отмена", null).show();
    }

    private void confirmAndRun(String title, String body, JSONObject srv, String action) {
        new AlertDialog.Builder(this).setTitle(title).setMessage(body)
            .setPositiveButton("Выполнить", (d, w) -> runServerAction(srv, action, null))
            .setNegativeButton("Отмена", null).show();
    }

    private void runServerAction(JSONObject srv, String action, String activateProtoKey) {
        String savedPass = srv.optString("password", "");
        String savedKey = srv.optString("key_pem", "");
        byte[] keyBytes = !savedKey.isEmpty() ? savedKey.getBytes(StandardCharsets.UTF_8) : pickedIdentity;
        if (!savedPass.isEmpty() || keyBytes != null) {
            executeSSH(srv, savedPass, keyBytes, action, activateProtoKey);
            return;
        }
        promptCredentialsAndRun(srv, action, activateProtoKey);
    }

    private void promptCredentialsAndRun(JSONObject srv, String action, String activateProtoKey) {
        LinearLayout form = new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(dp(18), dp(8), dp(18), 0);
        EditText passIn = field(form, pickedIdentity == null ? "Пароль SSH" : "Пароль ключа (если есть)", "",
            InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        CheckBox saveBox = new CheckBox(this);
        saveBox.setText("Сохранить пароль в защищённом хранилище");
        saveBox.setChecked(true);
        form.addView(saveBox);

        new AlertDialog.Builder(this)
            .setTitle("Доступ к " + srv.optString("name", srv.optString("host")))
            .setView(form)
            .setPositiveButton("Выполнить", (d, w) -> {
                String pw = passIn.getText().toString();
                if (saveBox.isChecked() && !pw.isEmpty()) {
                    try {
                        JSONObject fleet = loadFleet();
                        JSONObject cur = findById(fleet, srv.getString("id"));
                        if (cur != null) { cur.put("password", pw); saveFleet(fleet); }
                        srv.put("password", pw);
                    } catch (Exception ignored) {}
                }
                executeSSH(srv, pw, pickedIdentity, action, activateProtoKey);
            })
            .setNegativeButton("Отмена", null)
            .setNeutralButton(pickedIdentity == null ? "Выбрать SSH-ключ" : "Сбросить ключ", (d, w) -> {
                if (pickedIdentity != null) {
                    java.util.Arrays.fill(pickedIdentity, (byte) 0);
                    pickedIdentity = null;
                    promptCredentialsAndRun(srv, action, activateProtoKey);
                    return;
                }
                onIdentityPicked = () -> runServerAction(srv, action, activateProtoKey);
                startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT)
                    .addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), 44);
            }).show();
    }

    private static JSONObject findById(JSONObject fleet, String id) {
        JSONArray arr = fleet.optJSONArray("servers");
        if (arr == null) return null;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject s = arr.optJSONObject(i);
            if (s != null && id.equals(s.optString("id"))) return s;
        }
        return null;
    }

    private void executeSSH(JSONObject srvCopy, String password, byte[] keyBytes, String action, String activateProtoKey) {
        run(() -> {
            try {
                if ("socks-purge-both".equals(action)) {
                    String r1 = ServerSSH.run(this, srvCopy, password, "socks-pub-purge", keyBytes);
                    String r2 = ServerSSH.run(this, srvCopy, password, "socks-purge", keyBytes);
                    SshForward.stop(this);
                    JSONObject fleet = loadFleet();
                    JSONObject cur = findById(fleet, srvCopy.getString("id"));
                    if (cur != null) {
                        ServerSSH.apply(cur, r1);
                        ServerSSH.apply(cur, r2);
                        cur.remove("socks");
                        cur.remove("socks_pub");
                        saveFleet(fleet);
                    }
                    return "SOCKS5 остановлен и удалён с сервера.";
                }

                String record = ServerSSH.run(this, srvCopy, password, action, keyBytes);
                JSONObject fleet = loadFleet();
                JSONObject target = findById(fleet, srvCopy.getString("id"));
                if (target == null) target = srvCopy;
                if (srvCopy.has("pin")) target.put("pin", srvCopy.getString("pin"));
                if (srvCopy.has("device")) target.put("device", srvCopy.getString("device"));
                if (keyBytes != null) target.put("key_pem", new String(keyBytes, StandardCharsets.UTF_8));

                String msg = ServerSSH.apply(target, record);

                if (activateProtoKey != null && !target.optString(activateProtoKey, "").isEmpty()) {
                    target.put("active_proto", activateProtoKey);
                    target.put("active_uri", target.getString(activateProtoKey));
                } else if ("purge-all".equals(action)) {
                    SshForward.stop(this);
                    if (RemoteVpnService.busy(this)) RemoteVpnService.stop(this);
                } else if (action.endsWith("-purge")) {
                    String purgedProto = action.replace("-purge", "");
                    target.remove(purgedProto);
                    if (purgedProto.equals(target.optString("active_proto"))) {
                        String nextUri = pickNextActiveUri(target);
                        if (nextUri.isEmpty()) target.remove("active_uri");
                        else target.put("active_uri", nextUri);
                    }
                }
                saveFleet(fleet);
                return msg;
            } catch (ServerSSH.Untrusted first) {
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    new AlertDialog.Builder(this).setTitle("Ключ SSH сервера")
                        .setMessage(srvCopy.optString("host") + "\n" + first.fingerprint
                            + "\n\nСверьте отпечаток с консолью VPS. После подтверждения ключ будет закреплён.")
                        .setNegativeButton("Отмена", null)
                        .setPositiveButton("Ключ совпадает", (d, w) -> {
                            try {
                                srvCopy.put("pin", first.fingerprint);
                                executeSSH(srvCopy, password, keyBytes, action, activateProtoKey);
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
                pickedIdentity = key;
                Runnable next = onIdentityPicked;
                onIdentityPicked = null;
                if (next != null) next.run();
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
        input.setHint("HTTPS-подписка или ссылка узла");
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
}
