package dev.graybridge;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.graphics.*;
import android.graphics.drawable.*;
import android.net.Uri;
import android.net.VpnService;
import android.os.*;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.util.*;
import java.util.concurrent.Executors;
import org.json.*;

public class MainActivity extends Activity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final int BG = Color.rgb(11, 11, 13);
    private static final int PANEL = Color.rgb(20, 20, 24);
    private static final int PANEL_ELEV = Color.rgb(28, 28, 34);
    private static final int WHITE = Color.rgb(242, 242, 245);
    private static final int GRAY = Color.rgb(142, 142, 152);
    private static final int DIM = Color.rgb(92, 92, 102);
    private static final int BORDER = Color.rgb(40, 40, 48);
    private static final int BORDER_STRONG = Color.rgb(60, 60, 72);
    private static final int GREEN = Color.rgb(52, 211, 153);
    private static final int AMBER = Color.rgb(251, 191, 36);
    private static final int RED = Color.rgb(248, 113, 113);

    private final Handler handler = new Handler(Looper.getMainLooper());
    private LinearLayout heroCard;
    private View statusDot;
    private TextView status, hint, error, profile, retestButton, telegramButton;
    private TextView instagramSubtitle, extraSubtitle, telegramSubtitle, appsSubtitle, updateSummary;
    private Switch dpiSwitch, instagramSwitch, telegramSwitch, extrasSwitch;
    private PowerView power;
    private boolean binding;
    private boolean connecting;
    private boolean visible;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        if (dev.graybridge.Settings.prefs(this).getBoolean("remote_home", false) && !dev.graybridge.Settings.busy(this)) {
            startActivity(new Intent(this, RemoteActivity.class));
            finish();
            return;
        }
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
                v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            } else {
                v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                    insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            }
            return insets;
        });
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_STABLE | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN);
        setContentView(root);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, -1));

        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(18), dp(14), dp(18), dp(16));
        scroll.addView(page, new ScrollView.LayoutParams(-1, -2));

        // 1. Compact Header: Brand + version pill + quick Rules pill + overflow menu
        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);

        LinearLayout brandRow = new LinearLayout(this);
        brandRow.setGravity(Gravity.CENTER_VERTICAL);
        TextView name = label("SorryRKN", 21, WHITE);
        name.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        brandRow.addView(name);

        TextView verBadge = label("v" + BuildConfig.VERSION_NAME, 11, GRAY);
        verBadge.setTypeface(Typeface.MONOSPACE);
        verBadge.setPadding(dp(7), dp(2), dp(7), dp(2));
        verBadge.setBackground(shape(PANEL_ELEV, dp(6), BORDER));
        LinearLayout.LayoutParams verLp = new LinearLayout.LayoutParams(-2, -2);
        verLp.leftMargin = dp(8);
        brandRow.addView(verBadge, verLp);
        header.addView(brandRow, new LinearLayout.LayoutParams(0, -2, 1));

        TextView rulesBtn = label("Правила", 12, WHITE);
        rulesBtn.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        rulesBtn.setGravity(Gravity.CENTER);
        rulesBtn.setPadding(dp(12), dp(8), dp(12), dp(8));
        rulesBtn.setBackground(shape(PANEL, dp(10), BORDER));
        rulesBtn.setContentDescription("Мои ресурсы и правила");
        rulesBtn.setOnClickListener(v -> userRules());
        header.addView(rulesBtn, new LinearLayout.LayoutParams(-2, dp(38)));

        TextView menu = label("···", 20, GRAY);
        menu.setGravity(Gravity.CENTER);
        menu.setBackground(shape(PANEL, dp(10), BORDER));
        menu.setContentDescription("Настройки");
        LinearLayout.LayoutParams menuLp = new LinearLayout.LayoutParams(dp(42), dp(38));
        menuLp.leftMargin = dp(8);
        header.addView(menu, menuLp);
        menu.setOnClickListener(v -> showMenu(menu));
        page.addView(header);

        // 2. Top 3-Segment Mode Bar: Локальный | Свой сервер | Подписки
        LinearLayout modeBar = new LinearLayout(this);
        modeBar.setOrientation(LinearLayout.HORIZONTAL);
        modeBar.setPadding(dp(4), dp(4), dp(4), dp(4));
        modeBar.setBackground(shape(PANEL, dp(12), BORDER));
        LinearLayout.LayoutParams modeBarLp = new LinearLayout.LayoutParams(-1, -2);
        modeBarLp.topMargin = dp(12);
        page.addView(modeBar, modeBarLp);

        String[] modes = {"Локальный", "Свой сервер", "Подписки"};
        for (int i = 0; i < modes.length; i++) {
            final int idx = i;
            boolean active = idx == 0;
            TextView tab = label(modes[i], 12, active ? WHITE : GRAY);
            tab.setTypeface(Typeface.create(active ? "sans-serif-medium" : "sans-serif", Typeface.NORMAL));
            tab.setGravity(Gravity.CENTER);
            tab.setPadding(dp(6), dp(9), dp(6), dp(9));
            if (active) tab.setBackground(shape(PANEL_ELEV, dp(9), BORDER_STRONG));
            modeBar.addView(tab, new LinearLayout.LayoutParams(0, -2, 1));
            if (!active) {
                tab.setOnClickListener(v -> switchMode(idx == 1 ? "server" : "subscriptions"));
            }
        }

        // 3. Tactical Hero Card: Left Power button + Status/Subtitle + Right Quick Retest button
        heroCard = new LinearLayout(this);
        heroCard.setOrientation(LinearLayout.HORIZONTAL);
        heroCard.setGravity(Gravity.CENTER_VERTICAL);
        heroCard.setPadding(dp(14), dp(14), dp(14), dp(14));
        heroCard.setBackground(shape(PANEL, dp(18), BORDER));
        LinearLayout.LayoutParams heroLp = new LinearLayout.LayoutParams(-1, -2);
        heroLp.topMargin = dp(12);
        page.addView(heroCard, heroLp);

        power = new PowerView();
        heroCard.addView(power, new LinearLayout.LayoutParams(dp(68), dp(68)));
        power.setOnClickListener(v -> {
            if (dev.graybridge.Settings.busy(this)) BridgeService.stop(this);
            else connect();
        });

        LinearLayout heroCenter = new LinearLayout(this);
        heroCenter.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams hcLp = new LinearLayout.LayoutParams(0, -2, 1);
        hcLp.leftMargin = dp(14);
        hcLp.rightMargin = dp(8);
        heroCard.addView(heroCenter, hcLp);

        LinearLayout statusRow = new LinearLayout(this);
        statusRow.setGravity(Gravity.CENTER_VERTICAL);
        statusDot = new View(this);
        statusDot.setBackground(shape(DIM, dp(5), DIM));
        statusRow.addView(statusDot, new LinearLayout.LayoutParams(dp(8), dp(8)));

        status = label("Выключено", 17, WHITE);
        status.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        LinearLayout.LayoutParams stLp = new LinearLayout.LayoutParams(-2, -2);
        stLp.leftMargin = dp(8);
        statusRow.addView(status, stLp);
        heroCenter.addView(statusRow);

        hint = label("Нажмите кнопку для запуска", 12, GRAY);
        hint.setMaxLines(2);
        hint.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams hintLp = new LinearLayout.LayoutParams(-1, -2);
        hintLp.topMargin = dp(4);
        heroCenter.addView(hint, hintLp);

        error = label("", 11, AMBER);
        error.setMaxLines(2);
        error.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams errLp = new LinearLayout.LayoutParams(-1, -2);
        errLp.topMargin = dp(4);
        heroCenter.addView(error, errLp);

        retestButton = label("↻", 18, WHITE);
        retestButton.setGravity(Gravity.CENTER);
        retestButton.setBackground(shape(PANEL_ELEV, dp(12), BORDER_STRONG));
        retestButton.setContentDescription("Подобрать стратегию заново");
        retestButton.setOnClickListener(v -> {
            dev.graybridge.Settings.prefs(this).edit().putString("strategy", "auto").apply();
            BridgeService.retest(this);
            toast("Подбираем рабочую стратегию…");
        });
        retestButton.setOnLongClickListener(v -> {
            dev.graybridge.Settings.prefs(this).edit().putString("strategy", "auto").apply();
            BridgeService.retest(this, true);
            toast("Запущен расширенный подбор стратегий");
            return true;
        });
        heroCard.addView(retestButton, new LinearLayout.LayoutParams(dp(42), dp(42)));

        // 4. Live Tactical Rows Card (4 independent services, hot-reloadable without disconnect)
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(15), dp(2), dp(12), dp(2));
        card.setBackground(shape(PANEL, dp(18), BORDER));
        LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(-1, -2);
        cardLp.topMargin = dp(12);
        page.addView(card, cardLp);

        dpiSwitch = new Switch(this);
        LinearLayout dpiText = row(card, "YouTube, Discord и сайты  ›", "Авто · локальный обход DPI", dpiSwitch);
        profile = (TextView) dpiText.getChildAt(1);
        dpiText.setOnClickListener(v -> chooseProfile());

        addDivider(card);

        instagramSwitch = new Switch(this);
        LinearLayout instaText = row(card, "Instagram и Meta  ›", "Локальный обход DPI · свой IP", instagramSwitch);
        instagramSubtitle = (TextView) instaText.getChildAt(1);
        instaText.setOnClickListener(v -> new AlertDialog.Builder(this)
            .setTitle("Instagram и сайты со своим IP")
            .setMessage("Instagram и домены из списка «Обход DPI · свой IP» работают напрямую через локальный обход блокировок без смены вашего IP-адреса.\n\nЧтобы добавить собственные сайты, которые тормозят или не открываются у оператора, откройте «Мои ресурсы».")
            .setPositiveButton("Закрыть", null)
            .setNeutralButton("Мои ресурсы", (d, w) -> userRules())
            .show());

        addDivider(card);

        telegramSwitch = new Switch(this);
        LinearLayout telegramText = row(card, "Telegram MTProto  ›", "Локальный прокси · DC1–DC5", telegramSwitch);
        telegramSubtitle = (TextView) telegramText.getChildAt(1);
        telegramText.setOnClickListener(v -> showTelegramDialog());

        addDivider(card);

        extrasSwitch = new Switch(this);
        LinearLayout extraText = row(card, "Нейросети · Гео-DNS  ›", "ChatGPT · Claude · Gemini", extrasSwitch);
        extraSubtitle = (TextView) extraText.getChildAt(1);
        extraText.setOnClickListener(v -> DnsProfiles.show(this));

        dpiSwitch.setOnCheckedChangeListener((b, checked) -> {
            if (binding) return;
            dev.graybridge.Settings.prefs(this).edit().putBoolean("dpi", checked).apply();
            onServiceToggleChanged();
        });
        instagramSwitch.setOnCheckedChangeListener((b, checked) -> {
            if (binding) return;
            dev.graybridge.Settings.prefs(this).edit().putBoolean("instagram", checked).apply();
            onServiceToggleChanged();
        });
        telegramSwitch.setOnCheckedChangeListener((b, checked) -> {
            if (binding) return;
            dev.graybridge.Settings.prefs(this).edit().putBoolean("telegram", checked).apply();
            onServiceToggleChanged();
        });
        extrasSwitch.setOnCheckedChangeListener((b, checked) -> {
            if (binding) return;
            dev.graybridge.Settings.prefs(this).edit().putBoolean("extra_sites", checked).apply();
            onServiceToggleChanged();
        });

        // 4b. App Exclusions Card
        LinearLayout appsCard = new LinearLayout(this);
        appsCard.setOrientation(LinearLayout.VERTICAL);
        appsCard.setPadding(dp(15), dp(12), dp(15), dp(12));
        appsCard.setBackground(shape(PANEL, dp(16), BORDER));
        LinearLayout.LayoutParams appsLp = new LinearLayout.LayoutParams(-1, -2);
        appsLp.topMargin = dp(10);
        page.addView(appsCard, appsLp);

        TextView appsTitle = label("Исключения приложений  ›", 14, WHITE);
        appsTitle.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        appsCard.addView(appsTitle);

        appsSubtitle = label(AppExclusions.summary(this) + " · для VPN и обхода", 11, GRAY);
        LinearLayout.LayoutParams appsSubLp = new LinearLayout.LayoutParams(-1, -2);
        appsSubLp.topMargin = dp(3);
        appsCard.addView(appsSubtitle, appsSubLp);
        appsCard.setOnClickListener(v -> openAppExclusions());

        // 5. Bottom Tactical Action Bar: [ Telegram ↗ ] + [ Диагностика ]
        LinearLayout actionRow = new LinearLayout(this);
        actionRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams actionLp = new LinearLayout.LayoutParams(-1, -2);
        actionLp.topMargin = dp(12);
        page.addView(actionRow, actionLp);

        telegramButton = label("Telegram  ↗", 13, WHITE);
        telegramButton.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        telegramButton.setGravity(Gravity.CENTER);
        telegramButton.setBackground(shape(PANEL, dp(12), BORDER));
        telegramButton.setContentDescription("Добавить локальный прокси в Telegram");
        actionRow.addView(telegramButton, new LinearLayout.LayoutParams(0, dp(46), 1));
        telegramButton.setOnClickListener(v -> {
            String st = dev.graybridge.Settings.state(this);
            boolean ready = (st.equals("on") || st.equals("partial")) && dev.graybridge.Settings.telegram(this);
            if (!ready) {
                copyProxy();
                toast("Ссылка скопирована. Включите пульт для работы прокси.");
                return;
            }
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(dev.graybridge.Settings.link(this))));
            } catch (ActivityNotFoundException e) {
                copyProxy();
                toast("Ссылка скопирована. Откройте её в Telegram.");
            }
        });
        telegramButton.setOnLongClickListener(v -> {
            copyProxy();
            toast("Ссылка на прокси скопирована");
            return true;
        });

        TextView diagButton = label("Диагностика", 13, WHITE);
        diagButton.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        diagButton.setGravity(Gravity.CENTER);
        diagButton.setBackground(shape(PANEL, dp(12), BORDER));
        diagButton.setOnClickListener(v -> diagnostics());
        LinearLayout.LayoutParams diagLp = new LinearLayout.LayoutParams(0, dp(46), 1);
        diagLp.leftMargin = dp(10);
        actionRow.addView(diagButton, diagLp);

        TextView tile = label("＋ Плитка в быстрые настройки", 12, GRAY);
        tile.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams tileParams = new LinearLayout.LayoutParams(-1, dp(40));
        tileParams.topMargin = dp(4);
        page.addView(tile, tileParams);
        tile.setOnClickListener(v -> addTile());

        refresh();
        DataUpdates.request(this, false);
        DnsProfiles.check(this, false);
        if (getIntent().getBooleanExtra("connect", false)) {
            getIntent().removeExtra("connect");
            handler.post(this::connect);
        }
    }

    private void addDivider(LinearLayout parent) {
        View divider = new View(this);
        divider.setBackgroundColor(BORDER);
        parent.addView(divider, new LinearLayout.LayoutParams(-1, dp(1)));
    }

    private void switchMode(String remoteMode) {
        if (dev.graybridge.Settings.busy(this)) {
            BridgeService.stop(this);
            toast("Локальный обход остановлен");
        }
        dev.graybridge.Settings.prefs(this).edit()
            .putBoolean("remote_home", true)
            .putString("remote_mode", remoteMode)
            .apply();
        startActivity(new Intent(this, RemoteActivity.class));
        finish();
    }

    private void onServiceToggleChanged() {
        String st = dev.graybridge.Settings.state(this);
        if (st.equals("on") || st.equals("partial") || st.equals("starting")) {
            if (!dev.graybridge.Settings.vpn(this) && !dev.graybridge.Settings.telegram(this)) {
                BridgeService.stop(this);
            } else if (dev.graybridge.Settings.vpn(this) && VpnService.prepare(this) != null) {
                BridgeService.stop(this);
                handler.postDelayed(this::connect, 250);
            } else {
                BridgeService.reload(this);
            }
        }
        refresh();
    }

    private LinearLayout row(LinearLayout parent, String title, String subtitle, Switch toggle) {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(12), 0, dp(12));

        LinearLayout text = new LinearLayout(this);
        text.setOrientation(LinearLayout.VERTICAL);
        text.setPadding(0, dp(2), dp(8), dp(2));
        TextView a = label(title, 14, WHITE);
        a.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        text.addView(a);

        TextView b = label(subtitle, 11, GRAY);
        b.setMaxLines(1);
        b.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(-1, -2);
        bp.topMargin = dp(3);
        text.addView(b, bp);
        row.addView(text, new LinearLayout.LayoutParams(0, -2, 1));

        toggle.setContentDescription(title);
        StateListDrawable track = new StateListDrawable();
        GradientDrawable trackOn = shape(WHITE, dp(16), WHITE);
        trackOn.setSize(dp(46), dp(26));
        GradientDrawable trackOff = shape(BORDER, dp(16), BORDER);
        trackOff.setSize(dp(46), dp(26));
        track.addState(new int[]{android.R.attr.state_checked}, trackOn);
        track.addState(new int[]{}, trackOff);

        StateListDrawable thumb = new StateListDrawable();
        GradientDrawable thumbOn = shape(BG, dp(12), BG);
        thumbOn.setSize(dp(20), dp(20));
        GradientDrawable thumbOff = shape(GRAY, dp(12), GRAY);
        thumbOff.setSize(dp(20), dp(20));
        thumb.addState(new int[]{android.R.attr.state_checked}, thumbOn);
        thumb.addState(new int[]{}, thumbOff);

        toggle.setTrackDrawable(track);
        toggle.setThumbDrawable(thumb);
        toggle.setSplitTrack(false);
        toggle.setShowText(false);
        toggle.setSwitchMinWidth(dp(46));
        toggle.setPadding(dp(6), dp(8), dp(4), dp(8));
        row.addView(toggle, new LinearLayout.LayoutParams(dp(56), dp(44)));
        parent.addView(row);
        return text;
    }

    private void refresh() {
        String state = dev.graybridge.Settings.state(this);
        boolean liveVpn = dev.graybridge.Settings.prefs(this).getBoolean("vpn_active", false);
        boolean busy = dev.graybridge.Settings.busy(this);
        boolean stopping = state.equals("stopping");
        boolean active = state.equals("on") || state.equals("partial");

        binding = true;
        dpiSwitch.setChecked(dev.graybridge.Settings.dpi(this));
        instagramSwitch.setChecked(dev.graybridge.Settings.instagram(this));
        telegramSwitch.setChecked(dev.graybridge.Settings.telegram(this));
        extrasSwitch.setChecked(dev.graybridge.Settings.extras(this));
        dpiSwitch.setEnabled(!stopping);
        instagramSwitch.setEnabled(!stopping);
        telegramSwitch.setEnabled(!stopping);
        extrasSwitch.setEnabled(!stopping);
        binding = false;

        int dotColor = switch (state) {
            case "on" -> GREEN;
            case "partial", "starting", "stopping" -> AMBER;
            case "error" -> RED;
            default -> DIM;
        };
        statusDot.setBackground(shape(dotColor, dp(5), dotColor));
        int heroStroke = switch (state) {
            case "on" -> Color.argb(110, 52, 211, 153);
            case "partial", "starting" -> Color.argb(110, 251, 191, 36);
            case "error" -> Color.argb(120, 248, 113, 113);
            default -> BORDER;
        };
        heroCard.setBackground(shape(PANEL, dp(18), heroStroke));

        String chosen = dev.graybridge.Settings.prefs(this).getString("active_strategy", "");
        String modeLabel = Strategies.auto(this) ? "Авто" : "Вручную";
        profile.setText(modeLabel
            + (active && !chosen.isEmpty() ? " · " + chosen : " · локальный обход DPI"));

        int customDpiCount = UserRules.domains(this, "dpi_domains").length();
        String customDpiSuffix = customDpiCount > 0 ? " · +" + customDpiCount + " своих" : "";
        if (instagramSubtitle != null) {
            instagramSubtitle.setText((active && dev.graybridge.Settings.instagram(this)
                ? "Активен · свой IP" : "Локальный обход DPI · свой IP") + customDpiSuffix);
        }

        String dnsName = dev.graybridge.Settings.aiRelay(this)
            ? dev.graybridge.Settings.prefs(this).getString("dns_profile", "comss").toUpperCase(Locale.ROOT)
            : "Свой IP";
        if (extraSubtitle != null) {
            extraSubtitle.setText(active && dev.graybridge.Settings.extras(this)
                ? dnsName + " · " + chatgptStatus()
                : dnsName + " · ChatGPT · Claude · Gemini");
        }

        if (telegramSubtitle != null) {
            String relayTag = dev.graybridge.Settings.telegramRelay(this) ? "резерв вкл" : "напрямую";
            telegramSubtitle.setText(active && dev.graybridge.Settings.telegram(this)
                ? telegramStatus()
                : "MTProto · " + relayTag);
        }
        if (appsSubtitle != null) {
            appsSubtitle.setText(AppExclusions.summary(this) + " · для VPN и обхода");
        }

        status.setText(switch (state) {
            case "on" -> "Подключено";
            case "partial" -> liveVpn ? "Частичный доступ" : "Только Telegram";
            case "starting" -> "Подключение…";
            case "stopping" -> "Выключение…";
            case "error" -> "Не удалось включить";
            default -> "Выключено";
        });
        hint.setText(switch (state) {
            case "on" -> "Работает в фоне · переключение на лету";
            case "partial" -> liveVpn ? "Часть проверок не пройдена · нажмите ↻" : "Прокси Telegram активен · VPN выключен";
            case "starting" -> dev.graybridge.Settings.prefs(this).getString("probe_status", "Запускаем локальное соединение");
            case "stopping" -> "Закрываем соединения…";
            case "error" -> "Нажмите кнопку питания для повтора";
            default -> "Нажмите кнопку для запуска";
        });

        String detail = dev.graybridge.Settings.prefs(this).getString("error", "");
        if (active && dev.graybridge.Settings.vpn(this)) {
            detail = dev.graybridge.Settings.prefs(this).getString("probe_result", "");
        }
        error.setText(detail);
        error.setTextColor(state.equals("error") ? RED : GRAY);
        error.setVisibility((state.equals("error") || active) && !detail.isEmpty() ? View.VISIBLE : View.GONE);

        boolean canRetest = active && dev.graybridge.Settings.dpi(this);
        retestButton.setVisibility(canRetest ? View.VISIBLE : View.GONE);

        if (updateSummary != null) updateSummary.setText(updateText());
        boolean telegramReady = active && dev.graybridge.Settings.telegram(this);
        telegramButton.setAlpha(telegramReady ? 1f : .65f);

        power.on = active;
        power.busy = state.equals("starting") || stopping;
        power.setEnabled(!stopping);
        power.setContentDescription(busy ? "Выключить подключение" : "Включить подключение");
        power.invalidate();
    }

    private void showTelegramDialog() {
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(22), dp(12), dp(22), dp(8));

        TextView info = label(
            "Проверяются все пять дата-центров (DC1–DC5) коротким протокольным запросом без входа в аккаунт.\n\n"
            + telegramStatus(), 13, GRAY);
        body.addView(info);

        Switch relaySwitch = new Switch(this);
        LinearLayout relayRow = row(body, "Запасное реле Telegram",
            "Внешний WebSocket-маршрут, если прямой IP недоступен", relaySwitch);
        relayRow.setPadding(0, dp(8), 0, 0);
        relaySwitch.setChecked(dev.graybridge.Settings.telegramRelay(this));

        AlertDialog dialog = new AlertDialog.Builder(this)
            .setTitle("Telegram MTProto")
            .setView(body)
            .setPositiveButton("Сохранить", (d, w) -> {
                boolean prev = dev.graybridge.Settings.telegramRelay(this);
                boolean next = relaySwitch.isChecked();
                if (prev != next) {
                    dev.graybridge.Settings.prefs(this).edit().putBoolean("telegram_relay", next).apply();
                    String st = dev.graybridge.Settings.state(this);
                    if (st.equals("on") || st.equals("partial")) {
                        BridgeService.reload(this);
                        toast("Настройка реле Telegram применена");
                    }
                }
                refresh();
            })
            .setNeutralButton("Скопировать ссылку", (d, w) -> {
                copyProxy();
                toast("Ссылка на прокси скопирована");
            })
            .setNegativeButton("Закрыть", null)
            .create();
        dialog.show();
    }

    private String telegramStatus() {
        try {
            JSONObject traffic = new JSONObject(dev.graybridge.Settings.prefs(this).getString("traffic_report", "{}"));
            JSONObject check = traffic.optJSONObject("telegram_check");
            String state = check == null ? "unchecked" : check.optString("state", "unchecked");
            String replies = telegramReplies(check);
            return switch (state) {
                case "checking" -> "Проверяем ответ Telegram…";
                case "reachable" -> replies.isEmpty() ? "Ответ Telegram получен" : replies;
                case "partial" -> replies.isEmpty() ? "Ответили не все дата-центры" : replies;
                case "unavailable" -> replies.isEmpty() ? "Нет ответа · ищем маршрут" : replies;
                default -> "Ожидание проверки DC1–DC5";
            };
        } catch (JSONException e) {
            return "Ожидание проверки DC1–DC5";
        }
    }

    private static String telegramReplies(JSONObject check) {
        if (check == null) return "";
        JSONArray targets = check.optJSONArray("targets");
        int measured = 0;
        double latency = Double.NaN;
        if (targets != null) {
            for (int i = 0; i < targets.length(); i++) {
                JSONObject target = targets.optJSONObject(i);
                if (target != null && target.optString("state").equals("reachable")) {
                    measured++;
                    double value = target.optDouble("latency_ms", Double.NaN);
                    if (Double.isFinite(value) && value >= 0 && (!Double.isFinite(latency) || value < latency)) {
                        latency = value;
                    }
                }
            }
        }
        int total = check.optInt("total", targets == null ? 0 : targets.length());
        if (total <= 0) return "";
        int passed = Math.max(0, Math.min(total, check.optInt("passed", measured)));
        if (!Double.isFinite(latency)) latency = check.optDouble("latency_ms", Double.NaN);
        String timing = passed > 0 && Double.isFinite(latency) && latency >= 0 ? " · " + Math.round(latency) + " мс" : "";
        return passed + "/" + total + " DC" + timing;
    }

    private String chatgptStatus() {
        try {
            JSONObject traffic = new JSONObject(dev.graybridge.Settings.prefs(this).getString("traffic_report", "{}"));
            JSONObject check = traffic.optJSONObject("chatgpt_check");
            String state = check == null ? "unchecked" : check.optString("state", "unchecked");
            return switch (state) {
                case "checking" -> "ChatGPT: проверка…";
                case "reachable_public" -> "ChatGPT доступен";
                case "regional_refusal" -> "ChatGPT: отказ региона";
                case "challenge" -> "ChatGPT: проверка браузера";
                case "denied" -> "ChatGPT: отказ 403";
                case "login_unchecked" -> "ChatGPT: ответил";
                case "transport_error" -> "ChatGPT: нет связи";
                case "http_error" -> "ChatGPT: ошибка HTTP";
                default -> "ChatGPT: ожидание";
            };
        } catch (JSONException e) {
            return "ChatGPT: ожидание";
        }
    }

    private void connect() {
        if (connecting || dev.graybridge.Settings.busy(this)) return;
        if (!dev.graybridge.Settings.vpn(this) && !dev.graybridge.Settings.telegram(this)) {
            toast("Включите хотя бы один сервис на пульте");
            return;
        }
        connecting = true;
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                && !dev.graybridge.Settings.prefs(this).getBoolean("notificationAsked", false)) {
            dev.graybridge.Settings.prefs(this).edit().putBoolean("notificationAsked", true).apply();
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 101);
        } else {
            prepareVpn();
        }
    }

    private void prepareVpn() {
        Intent consent = dev.graybridge.Settings.vpn(this) ? VpnService.prepare(this) : null;
        if (consent != null) startActivityForResult(consent, 100);
        else {
            connecting = false;
            BridgeService.start(this);
        }
    }

    @Override public void onRequestPermissionsResult(int code, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(code, permissions, results);
        if (code == 101) prepareVpn();
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == 100) {
            connecting = false;
            if (result == RESULT_OK) BridgeService.start(this);
            else toast("Подключение требует разрешения VPN");
        }
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (visible && !isFinishing()) AppUpdates.check(this, false);
        if (intent.getBooleanExtra("connect", false)) {
            intent.removeExtra("connect");
            connect();
        }
    }

    @Override protected void onStart() {
        super.onStart();
        visible = true;
        if (!isFinishing()) AppUpdates.check(this, false);
    }

    @Override protected void onStop() {
        visible = false;
        super.onStop();
    }

    @Override protected void onResume() {
        super.onResume();
        if (isFinishing()) return;
        AppUpdates.resume(this);
        dev.graybridge.Settings.prefs(this).registerOnSharedPreferenceChangeListener(this);
        refresh();
        DnsProfiles.check(this, false);
    }

    @Override protected void onPause() {
        dev.graybridge.Settings.prefs(this).unregisterOnSharedPreferenceChangeListener(this);
        super.onPause();
    }

    @Override public void onSharedPreferenceChanged(SharedPreferences prefs, String key) {
        handler.post(this::refresh);
    }

    private void chooseProfile() {
        String curState = dev.graybridge.Settings.state(this);
        if (curState.equals("starting") || curState.equals("stopping")) {
            toast("Дождитесь завершения переключения");
            return;
        }
        java.util.concurrent.ExecutorService task = Executors.newSingleThreadExecutor();
        task.execute(() -> {
            try {
                List<Strategies.Profile> profiles = Strategies.load(this);
                handler.post(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    String mode = dev.graybridge.Settings.prefs(this).getString("strategy", "auto");
                    String[] names = new String[profiles.size() + 1];
                    names[0] = "Автоматически — быстрый подбор";
                    int selected = 0;
                    for (int i = 0; i < profiles.size(); i++) {
                        names[i + 1] = profiles.get(i).name + (profiles.get(i).id.startsWith("adapt-") ? " · адаптация" : "");
                        if (profiles.get(i).id.equals(mode)) selected = i + 1;
                    }
                    new AlertDialog.Builder(this).setTitle("Стратегия обхода DPI")
                        .setSingleChoiceItems(names, selected, (dialog, which) -> {
                            String chosen = which == 0 ? "auto" : profiles.get(which - 1).id;
                            dev.graybridge.Settings.prefs(this).edit().putString("strategy", chosen).apply();
                            dialog.dismiss();
                            String st = dev.graybridge.Settings.state(this);
                            if ((st.equals("on") || st.equals("partial")) && dev.graybridge.Settings.dpi(this)) {
                                BridgeService.retest(this);
                                toast("Применяем выбранную стратегию…");
                            }
                            refresh();
                        }).setNegativeButton("Закрыть", null).show();
                });
            } catch (Exception e) {
                handler.post(() -> toast("Не удалось прочитать стратегии"));
            } finally {
                task.shutdown();
            }
        });
    }

    private void showMenu(View anchor) {
        PopupMenu popup = new PopupMenu(this, anchor);
        String st = dev.graybridge.Settings.state(this);
        boolean canRetry = (st.equals("on") || st.equals("partial")) && dev.graybridge.Settings.dpi(this);
        popup.getMenu().add("Подобрать заново").setEnabled(canRetry);
        popup.getMenu().add("Расширенный подбор").setEnabled(canRetry);
        popup.getMenu().add("Маршруты").setEnabled(!st.equals("starting") && !st.equals("stopping"));
        popup.getMenu().add("DNS и нейросети");
        popup.getMenu().add("Мои ресурсы");
        popup.getMenu().add("Исключения приложений");
        popup.getMenu().add("Обновить приложение");
        popup.getMenu().add("Обновления списков");
        popup.getMenu().add("Работа в фоне");
        popup.getMenu().add("О приложении");
        popup.setOnMenuItemClickListener(item -> {
            switch (item.getTitle().toString()) {
                case "DNS и нейросети" -> DnsProfiles.show(this);
                case "Маршруты" -> routeSettings();
                case "Мои ресурсы" -> userRules();
                case "Исключения приложений" -> openAppExclusions();
                case "Обновить приложение" -> AppUpdates.show(this);
                case "Работа в фоне" -> battery();
                case "Обновления списков" -> updates();
                case "Подобрать заново" -> {
                    dev.graybridge.Settings.prefs(this).edit().putString("strategy", "auto").apply();
                    BridgeService.retest(this);
                }
                case "Расширенный подбор" -> {
                    dev.graybridge.Settings.prefs(this).edit().putString("strategy", "auto").apply();
                    BridgeService.retest(this, true);
                }
                default -> about();
            }
            return true;
        });
        popup.show();
    }

    private String aiRouteText() {
        return dev.graybridge.Settings.aiRelay(this)
            ? "Нейросети используют Гео-DNS реле с зарубежным IP для обхода региональных ограничений. HTTPS проверяется приложением или браузером."
            : "Нейросети подключаются со своим IP через локальный обход DPI. Региональные ограничения самого сервиса при этом сохраняются.";
    }

    private String telegramRouteText() {
        return dev.graybridge.Settings.telegramRelay(this)
            ? "Запасное реле Telegram включено на случай недоступности прямых IP."
            : "Telegram работает только напрямую к серверам Telegram без внешних реле.";
    }

    private void routeSettings() {
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(24), dp(8), dp(24), dp(12));
        body.addView(label("Изменения применяются сразу, без ручного выключения.", 13, GRAY));
        Switch aiRelay = new Switch(this);
        row(body, "Зарубежное реле для нейросетей", "ChatGPT · Claude · Gemini и список Гео-DNS.", aiRelay);
        aiRelay.setChecked(dev.graybridge.Settings.aiRelay(this));
        Switch telegramRelay = new Switch(this);
        row(body, "Запасное реле Telegram", "Резервный WebSocket-маршрут при блокировке прямых IP.", telegramRelay);
        telegramRelay.setChecked(dev.graybridge.Settings.telegramRelay(this));
        body.addView(label("Instagram, YouTube и Discord всегда идут со своим IP через локальный обход DPI.", 12, GRAY));
        ScrollView scroll = new ScrollView(this);
        scroll.addView(body);
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("Маршруты").setView(scroll)
            .setPositiveButton("Сохранить", null).setNegativeButton("Отмена", null).create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String state = dev.graybridge.Settings.state(this);
            if (state.equals("starting") || state.equals("stopping")) {
                toast("Дождитесь завершения переключения");
                return;
            }
            boolean changed = aiRelay.isChecked() != dev.graybridge.Settings.aiRelay(this)
                || telegramRelay.isChecked() != dev.graybridge.Settings.telegramRelay(this);
            if (changed) {
                dev.graybridge.Settings.prefs(this).edit()
                    .putBoolean("ai_relay", aiRelay.isChecked())
                    .putBoolean("telegram_relay", telegramRelay.isChecked())
                    .apply();
            }
            dialog.dismiss();
            if (changed && (state.equals("on") || state.equals("partial"))) {
                BridgeService.reload(this);
                toast("Маршруты обновлены на лету");
            } else {
                toast(changed ? "Маршруты сохранены" : "Маршруты не изменились");
            }
            refresh();
        }));
        dialog.show();
    }

    private void openAppExclusions() {
        String st = dev.graybridge.Settings.state(this);
        if (st.equals("starting") || st.equals("stopping")) {
            toast("Дождитесь завершения переключения");
            return;
        }
        AppExclusions.show(this, () -> {
            String now = dev.graybridge.Settings.state(this);
            if (now.equals("on") || now.equals("partial")) {
                BridgeService.reload(this);
                toast("Исключения сохранены и применены");
            } else {
                toast("Исключения сохранены");
            }
            refresh();
        });
    }

    AlertDialog userRules() {
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(22), dp(8), dp(22), dp(12));
        TextView note = label("По одному домену или ссылке в строке (включая поддомены). Приоритет: Напрямую → Нейросети → Обход DPI.", 12, GRAY);
        body.addView(note);

        TextView dpiTitle = label("Обход DPI · свой IP", 14, WHITE);
        dpiTitle.setPadding(0, dp(10), 0, 0);
        body.addView(dpiTitle);
        EditText dpi = domainInput(UserRules.text(this, "dpi_domains"));
        dpi.setId(UserRules.DPI_FIELD_ID);
        dpi.setContentDescription("Обход DPI со своим IP");
        body.addView(dpi);

        TextView geoTitle = label("Маршрут нейросетей · Гео-DNS", 14, WHITE);
        geoTitle.setPadding(0, dp(8), 0, 0);
        body.addView(geoTitle);
        EditText geo = domainInput(UserRules.text(this, "geo_domains"));
        geo.setId(UserRules.GEO_FIELD_ID);
        geo.setContentDescription("Маршрут нейросетей");
        body.addView(geo);

        TextView directTitle = label("Напрямую · без обработки DPI", 14, WHITE);
        directTitle.setPadding(0, dp(8), 0, 0);
        body.addView(directTitle);
        EditText direct = domainInput(UserRules.text(this, "direct_domains"));
        direct.setId(UserRules.DIRECT_FIELD_ID);
        direct.setContentDescription("Напрямую");
        body.addView(direct);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(body);
        AlertDialog dialog = new AlertDialog.Builder(this)
            .setTitle("Мои ресурсы")
            .setView(scroll)
            .setPositiveButton("Сохранить", null)
            .setNegativeButton("Отмена", null)
            .create();
        dialog.setOnShowListener(d -> {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(WHITE);
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
                String dpiValue, geoValue, directValue;
                try { dpiValue = UserRules.parse(dpi.getText().toString()); }
                catch (IllegalArgumentException e) { dpi.setError(e.getMessage()); return; }
                try { geoValue = UserRules.parse(geo.getText().toString()); }
                catch (IllegalArgumentException e) { geo.setError(e.getMessage()); return; }
                try { directValue = UserRules.parse(direct.getText().toString()); }
                catch (IllegalArgumentException e) { direct.setError(e.getMessage()); return; }
                dev.graybridge.Settings.prefs(this).edit()
                    .putString("dpi_domains", dpiValue)
                    .putString("geo_domains", geoValue)
                    .putString("direct_domains", directValue)
                    .apply();
                dialog.dismiss();
                String st = dev.graybridge.Settings.state(this);
                if (st.equals("on") || st.equals("partial")) {
                    BridgeService.reload(this);
                    toast("Правила сохранены и применены");
                } else {
                    toast("Правила сохранены");
                }
                refresh();
            });
        });
        dialog.show();
        return dialog;
    }

    private EditText domainInput(String value) {
        EditText input = new EditText(this);
        input.setText(value);
        input.setTextSize(13);
        input.setTextColor(WHITE);
        input.setHint("example.com\nhttps://service.example.org");
        input.setHintTextColor(DIM);
        input.setMinLines(2);
        input.setMaxLines(4);
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT
            | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
            | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        input.setGravity(Gravity.TOP);
        input.setFilters(new android.text.InputFilter[]{new android.text.InputFilter.LengthFilter(UserRules.MAX_TEXT)});
        return input;
    }

    private String diagnosticText() {
        try {
            SharedPreferences prefs = dev.graybridge.Settings.prefs(this);
            JSONObject report = new JSONObject();
            report.put("version", BuildConfig.VERSION_NAME)
                .put("device", Build.MANUFACTURER + " " + Build.MODEL)
                .put("reconnect_count", prefs.getInt("reconnect_count", 0))
                .put("network_reconnect_count", prefs.getInt("network_reconnect_count", 0))
                .put("custom_dpi_count", UserRules.domains(this, "dpi_domains").length())
                .put("custom_geo_count", UserRules.domains(this, "geo_domains").length())
                .put("custom_direct_count", UserRules.domains(this, "direct_domains").length())
                .put("excluded_apps_count", AppExclusions.count(this))
                .put("android", Build.VERSION.RELEASE)
                .put("sdk", Build.VERSION.SDK_INT)
                .put("state", dev.graybridge.Settings.state(this))
                .put("strategy", prefs.getString("active_strategy", ""))
                .put("instagram", dev.graybridge.Settings.instagram(this))
                .put("extra_sites", dev.graybridge.Settings.extras(this))
                .put("own_ip", !dev.graybridge.Settings.aiRelay(this))
                .put("ai_relay", dev.graybridge.Settings.aiRelay(this))
                .put("telegram_relay", dev.graybridge.Settings.telegramRelay(this))
                .put("checks", new JSONArray(prefs.getString("probe_report", "[]")))
                .put("traffic", new JSONObject(prefs.getString("traffic_report", "{}")))
                .put("network", new JSONObject(prefs.getString("network_report", "{}")))
                .put("private_dns_mode", Settings.Global.getString(getContentResolver(), "private_dns_mode"))
                .put("native_exit", prefs.contains("native_exit") ? prefs.getInt("native_exit", 0) : JSONObject.NULL);
            if (dev.graybridge.Settings.state(this).equals("on") && dev.graybridge.Settings.vpn(this)) {
                long[] stats = NativeTunnel.stats();
                report.put("tun", new JSONObject()
                    .put("tx_packets", stats[0]).put("tx_bytes", stats[1])
                    .put("rx_packets", stats[2]).put("rx_bytes", stats[3]));
            }
            return report.toString(2);
        } catch (Exception | LinkageError e) {
            return "Не удалось сформировать диагностику: " + e.getClass().getSimpleName();
        }
    }

    private void diagnostics() {
        String text = diagnosticText();
        ScrollView scroll = new ScrollView(this);
        TextView body = label(text, 11, GRAY);
        body.setTypeface(Typeface.MONOSPACE);
        body.setPadding(dp(20), dp(12), dp(20), dp(12));
        body.setTextIsSelectable(true);
        scroll.addView(body);
        new AlertDialog.Builder(this).setTitle("Диагностика").setView(scroll)
            .setPositiveButton("Закрыть", null)
            .setNeutralButton("Копировать", (d, w) -> {
                ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE))
                    .setPrimaryClip(ClipData.newPlainText("SorryRKN diagnostics", text));
                toast("Диагностика скопирована");
            }).show();
    }

    private String updateText() {
        long checked = dev.graybridge.Settings.prefs(this).getLong("update_checked", 0);
        return dev.graybridge.Settings.prefs(this).getString("update_status", "Используются данные из APK")
            + (checked > 0 ? "\n\nПроверено: " + DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date(checked)) : "")
            + "\n\nСписки сайтов, исключения, домены Telegram и совместимые параметры стратегий обновляются с GitHub.";
    }

    private void updates() {
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(24), dp(12), dp(24), dp(12));
        updateSummary = label(updateText(), 13, GRAY);
        body.addView(updateSummary);
        Switch automatic = new Switch(this);
        automatic.setText("Автоматически, раз в сутки");
        automatic.setTextSize(13);
        automatic.setTextColor(WHITE);
        automatic.setPadding(0, dp(20), 0, 0);
        automatic.setChecked(dev.graybridge.Settings.prefs(this).getBoolean("auto_updates", true));
        automatic.setOnCheckedChangeListener((v, on) -> {
            dev.graybridge.Settings.prefs(this).edit().putBoolean("auto_updates", on).apply();
            DataUpdates.schedule(this);
            if (on) DataUpdates.request(this, false);
        });
        body.addView(automatic);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(body);
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("Обновления списков").setView(scroll)
            .setPositiveButton("Закрыть", null).setNeutralButton("Проверить сейчас", null).create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> {
            DataUpdates.request(this, true);
            toast("Проверяем обновления");
        }));
        dialog.setOnDismissListener(d -> updateSummary = null);
        dialog.show();
    }

    private void addTile() {
        if (Build.VERSION.SDK_INT >= 33) {
            getSystemService(StatusBarManager.class).requestAddTileService(
                new ComponentName(this, BridgeTile.class), "SorryRKN",
                Icon.createWithResource(this, R.drawable.ic_bridge), getMainExecutor(),
                result -> {
                    if (result == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_NOT_ADDED) {
                        toast("Можно добавить SorryRKN через редактирование шторки");
                    }
                });
        } else {
            new AlertDialog.Builder(this).setTitle("Быстрые настройки")
                .setMessage("Откройте шторку → редактирование плиток → перетащите SorryRKN к Wi-Fi и Bluetooth.")
                .setPositiveButton("Понятно", null).show();
        }
    }

    private void battery() {
        PowerManager pm = getSystemService(PowerManager.class);
        if (pm.isIgnoringBatteryOptimizations(getPackageName())) {
            toast("Фоновая работа уже разрешена");
            return;
        }
        new AlertDialog.Builder(this).setTitle("Работа в фоне")
            .setMessage("Разрешите работу без ограничений батареи, чтобы Android реже останавливал подключение при выключенном экране.")
            .setPositiveButton("Открыть настройки", (d, w) -> {
                try {
                    startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
                } catch (ActivityNotFoundException e) {
                    startActivity(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + getPackageName())));
                }
            }).setNegativeButton("Позже", null).show();
    }

    private void about() {
        new AlertDialog.Builder(this).setTitle("SorryRKN " + BuildConfig.VERSION_NAME)
            .setMessage("Локальный обход DPI, Гео-DNS и Telegram MTProto-прокси. Android показывает значок VPN для локальной маршрутизации на устройстве.\n\n"
                + aiRouteText() + "\n\n" + telegramRouteText()
                + "\n\nПубличные проверки подтверждают сетевой и HTTPS-ответ, но не проверяют вход в аккаунт, подписки, звонки или видеопоток на каждом операторе. Локальный прокси Telegram: 127.0.0.1:"
                + dev.graybridge.Settings.telegramPort(this) + ".")
            .setPositiveButton("Закрыть", null)
            .setNeutralButton("Лицензии", (d, w) -> licenses())
            .show();
    }

    private void licenses() {
        StringBuilder text = new StringBuilder();
        try {
            for (String name : getAssets().list("licenses")) {
                text.append(name).append("\n\n");
                try (InputStream in = getAssets().open("licenses/" + name);
                     ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                    byte[] buf = new byte[8192];
                    int count;
                    while ((count = in.read(buf)) >= 0) out.write(buf, 0, count);
                    text.append(new String(out.toByteArray(), StandardCharsets.UTF_8)).append("\n\n");
                }
            }
        } catch (IOException e) {
            text.append("Не удалось прочитать лицензии");
        }
        ScrollView scroll = new ScrollView(this);
        TextView body = label(text.toString(), 11, GRAY);
        body.setPadding(dp(20), dp(12), dp(20), dp(12));
        scroll.addView(body);
        new AlertDialog.Builder(this).setTitle("Открытые компоненты").setView(scroll)
            .setPositiveButton("Закрыть", null).show();
    }

    private void copyProxy() {
        ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE))
            .setPrimaryClip(ClipData.newPlainText("Telegram proxy", dev.graybridge.Settings.link(this)));
    }

    private void toast(String text) { Toast.makeText(this, text, Toast.LENGTH_SHORT).show(); }

    private TextView label(String text, int size, int color) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setFontFeatureSettings("kern");
        return view;
    }

    private GradientDrawable shape(int fill, int radius, int stroke) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(fill);
        d.setCornerRadius(radius);
        d.setStroke(dp(1), stroke);
        return d;
    }

    private int dp(float value) { return Math.round(value * getResources().getDisplayMetrics().density); }

    private class PowerView extends View {
        boolean on, busy;
        final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);

        PowerView() {
            super(MainActivity.this);
            setClickable(true);
            setFocusable(true);
        }

        @Override protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            float cx = getWidth() / 2f, cy = getHeight() / 2f;
            float r = Math.min(getWidth(), getHeight()) / 2f - dp(4);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(dp(1));
            paint.setColor(on ? GREEN : BORDER_STRONG);
            canvas.drawCircle(cx, cy, r + dp(3), paint);
            paint.setStyle(Paint.Style.FILL);
            paint.setColor(on ? WHITE : PANEL_ELEV);
            canvas.drawCircle(cx, cy, r, paint);
            if (busy) {
                paint.setStyle(Paint.Style.STROKE);
                paint.setStrokeWidth(dp(2));
                paint.setColor(AMBER);
                float angle = (SystemClock.uptimeMillis() % 1400) * 360f / 1400;
                canvas.drawArc(cx - r - dp(3), cy - r - dp(3), cx + r + dp(3), cy + r + dp(3), angle, 80, false, paint);
                postInvalidateDelayed(32);
            }
            Drawable mark = getDrawable(R.drawable.ic_bridge).mutate();
            mark.setTint(on ? BG : WHITE);
            int half = Math.max(dp(15), Math.round(r * 0.52f));
            mark.setBounds((int) cx - half, (int) cy - half, (int) cx + half, (int) cy + half);
            mark.draw(canvas);
        }

        @Override public boolean onTouchEvent(MotionEvent event) {
            if (event.getAction() == MotionEvent.ACTION_DOWN) animate().scaleX(.95f).scaleY(.95f).setDuration(90).start();
            if (event.getAction() == MotionEvent.ACTION_UP || event.getAction() == MotionEvent.ACTION_CANCEL) animate().scaleX(1).scaleY(1).setDuration(130).start();
            return super.onTouchEvent(event);
        }

        @Override public boolean performClick() { return super.performClick(); }
    }
}
