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
import android.view.*;
import android.widget.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Executors;
import java.text.DateFormat;
import org.json.*;

public class MainActivity extends Activity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final int BG = Color.rgb(11,11,12), PANEL = Color.rgb(21,21,23), WHITE = Color.rgb(238,238,238), GRAY = Color.rgb(133,133,140), BORDER = Color.rgb(44,44,48);
    private final Handler handler = new Handler(Looper.getMainLooper());
    private TextView status, hint, error, profile, telegramButton;
    private Switch dpiSwitch, telegramSwitch, extrasSwitch;
    private PowerView power;
    private boolean binding;
    private boolean connecting;
    private TextView updateSummary, extraSubtitle, telegramSubtitle;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
                v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            } else v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(), insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
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
        page.setPadding(dp(28), dp(28), dp(28), dp(24));
        scroll.addView(page, new ScrollView.LayoutParams(-1, -1));

        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout brand = new LinearLayout(this);
        brand.setOrientation(LinearLayout.VERTICAL);
        TextView eyebrow = label("ЛОКАЛЬНОЕ СОЕДИНЕНИЕ", 10, GRAY);
        eyebrow.setLetterSpacing(.14f);
        brand.addView(eyebrow);
        TextView name = label("SorryRKN", 30, WHITE);
        name.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        LinearLayout.LayoutParams nameParams = new LinearLayout.LayoutParams(-2,-2);
        nameParams.topMargin = dp(8);
        brand.addView(name, nameParams);
        header.addView(brand, new LinearLayout.LayoutParams(0, -2, 1));
        TextView menu = label("···", 30, GRAY);
        menu.setGravity(Gravity.CENTER); menu.setContentDescription("Настройки");
        header.addView(menu, new LinearLayout.LayoutParams(dp(48), dp(48)));
        menu.setOnClickListener(v -> showMenu(menu));
        page.addView(header);

        LinearLayout center = new LinearLayout(this);
        center.setOrientation(LinearLayout.VERTICAL);
        center.setGravity(Gravity.CENTER);
        center.setPadding(0,dp(38),0,dp(36));
        page.addView(center, new LinearLayout.LayoutParams(-1,0,1));
        power = new PowerView();
        center.addView(power, new LinearLayout.LayoutParams(dp(172),dp(172)));
        power.setOnClickListener(v -> { if (dev.graybridge.Settings.busy(this)) BridgeService.stop(this); else connect(); });
        status = label("Выключено", 23, WHITE);
        status.setTypeface(Typeface.create("sans-serif-medium",Typeface.NORMAL));
        LinearLayout.LayoutParams statusParams = new LinearLayout.LayoutParams(-2,-2); statusParams.topMargin=dp(24);
        center.addView(status,statusParams);
        hint = label("Нажмите, чтобы подключиться", 13, GRAY);
        hint.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams hintParams = new LinearLayout.LayoutParams(-1,-2); hintParams.topMargin=dp(9);
        center.addView(hint,hintParams);
        error = label("",12,GRAY); error.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams errParams = new LinearLayout.LayoutParams(-1,-2); errParams.topMargin=dp(14);
        center.addView(error,errParams);

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(18),dp(4),dp(18),dp(4));
        card.setBackground(shape(PANEL,dp(20),BORDER));
        page.addView(card,new LinearLayout.LayoutParams(-1,-2));
        dpiSwitch = new Switch(this);
        LinearLayout dpiText = row(card, "Обход DPI", "YouTube · Discord · сайты", dpiSwitch);
        profile = (TextView)dpiText.getChildAt(1);
        dpiText.setOnClickListener(v -> { if (!dev.graybridge.Settings.busy(this)) chooseProfile(); });
        View divider = new View(this); divider.setBackgroundColor(BORDER);
        card.addView(divider,new LinearLayout.LayoutParams(-1,dp(1)));
        telegramSwitch = new Switch(this);
        LinearLayout telegramText=row(card,"Telegram", "MTProto / WebSocket",telegramSwitch);
        telegramSubtitle=(TextView)telegramText.getChildAt(1);
        telegramText.setOnClickListener(v->new AlertDialog.Builder(this).setTitle("Проверка Telegram")
            .setMessage("Приложение отправляет короткий запрос через собственный локальный прокси и ждёт ответ Telegram. Проверяются два основных дата-центра — DC2 и DC4. Открытого порта или соединения WebSocket для успеха недостаточно.\n\nПроверка не входит в аккаунт и не проверяет загрузку медиа. Она работает в фоне и не перезапускает ваши подключения.\n\nВ диагностике отдельно показаны этапы исходящих подключений, причины отказов и паузы перед повтором. Счётчики Telegram относятся к текущему включению. Сообщения и секрет прокси в отчёт не попадают.")
            .setPositiveButton("Понятно",null).show());
        View extrasDivider=new View(this);extrasDivider.setBackgroundColor(BORDER);
        card.addView(extrasDivider,new LinearLayout.LayoutParams(-1,dp(1)));
        extrasSwitch=new Switch(this);
        LinearLayout extraText=row(card,"Нейросети и Instagram","ChatGPT · Claude · Gemini · Instagram",extrasSwitch);
        extraSubtitle=(TextView)extraText.getChildAt(1);
        extraText.setOnClickListener(v->new AlertDialog.Builder(this).setTitle("Нейросети и Instagram")
            .setMessage("Прямое подключение с обходом DPI. Сайты видят IP вашего подключения; внешние VPN и DNS-реле не используются.\n\n"+chatgptStatus()+"\nПроверка страницы не проверяет вход в аккаунт и отправку сообщений. Если сервис сам запрещает доступ из страны вашего IP, обход DPI этот отказ не снимает.")
            .setPositiveButton("Закрыть",null).setNeutralButton("Страны ChatGPT",(d,w)->{
                try {startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse("https://help.openai.com/en/articles/7947663-chatgpt-supported-countries")));}
                catch(ActivityNotFoundException e) {toast("Не установлен браузер");}
            }).show());
        extrasSwitch.setOnCheckedChangeListener((button,checked)->{
            if(!binding)dev.graybridge.Settings.prefs(this).edit().putBoolean("extra_sites",checked).apply();
        });
        dpiSwitch.setOnCheckedChangeListener((button, checked) -> {
            if (!binding) dev.graybridge.Settings.prefs(this).edit().putBoolean("dpi",checked).apply();
        });
        telegramSwitch.setOnCheckedChangeListener((button, checked) -> {
            if (!binding) dev.graybridge.Settings.prefs(this).edit().putBoolean("telegram",checked).apply();
        });

        telegramButton = label("Подключить Telegram  ↗", 14, WHITE);
        telegramButton.setTypeface(Typeface.create("sans-serif-medium",Typeface.NORMAL));
        telegramButton.setGravity(Gravity.CENTER);
        telegramButton.setBackground(shape(PANEL, dp(14), BORDER));
        telegramButton.setContentDescription("Добавить локальный прокси в Telegram");
        LinearLayout.LayoutParams telegramParams = new LinearLayout.LayoutParams(-1,dp(52)); telegramParams.topMargin=dp(16);
        page.addView(telegramButton,telegramParams);
        telegramButton.setOnClickListener(v -> {
            try { startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse(dev.graybridge.Settings.link(this)))); }
            catch (ActivityNotFoundException e) { copyProxy(); toast("Ссылка скопирована. Откройте её на устройстве с Telegram."); }
        });
        telegramButton.setOnLongClickListener(v -> { copyProxy(); toast("Ссылка на прокси скопирована"); return true; });
        TextView tile = label("＋  Добавить в быстрые настройки",12,GRAY);
        tile.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams tileParams = new LinearLayout.LayoutParams(-1,dp(48)); tileParams.topMargin=dp(5);
        page.addView(tile,tileParams); tile.setOnClickListener(v -> addTile());
        TextView footer = label("БЕЗ ROOT  /  ЛОКАЛЬНЫЙ VPN",9,GRAY);
        footer.setLetterSpacing(.12f); footer.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams footerParams = new LinearLayout.LayoutParams(-1,-2); footerParams.topMargin=dp(15);
        page.addView(footer,footerParams);
        refresh();
        DataUpdates.request(this, false);
        if (getIntent().getBooleanExtra("connect",false)) { getIntent().removeExtra("connect"); handler.post(this::connect); }
    }

    private LinearLayout row(LinearLayout parent, String title, String subtitle, Switch toggle) {
        LinearLayout row = new LinearLayout(this); row.setGravity(Gravity.CENTER_VERTICAL); row.setPadding(0,dp(18),0,dp(18));
        LinearLayout text = new LinearLayout(this); text.setOrientation(LinearLayout.VERTICAL);
        TextView a = label(title,15,WHITE); a.setTypeface(Typeface.create("sans-serif-medium",Typeface.NORMAL)); text.addView(a);
        TextView b = label(subtitle,11,GRAY); LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(-1,-2); bp.topMargin=dp(6); text.addView(b,bp);
        row.addView(text,new LinearLayout.LayoutParams(0,-2,1));
        toggle.setContentDescription(title);
        android.graphics.drawable.StateListDrawable track=new android.graphics.drawable.StateListDrawable();
        GradientDrawable trackOn=shape(WHITE,dp(18),WHITE);trackOn.setSize(dp(50),dp(30));
        GradientDrawable trackOff=shape(BORDER,dp(18),BORDER);trackOff.setSize(dp(50),dp(30));
        track.addState(new int[]{android.R.attr.state_checked},trackOn);track.addState(new int[]{},trackOff);
        android.graphics.drawable.StateListDrawable thumb=new android.graphics.drawable.StateListDrawable();
        GradientDrawable thumbOn=shape(BG,dp(14),BG);thumbOn.setSize(dp(24),dp(24));
        GradientDrawable thumbOff=shape(GRAY,dp(14),GRAY);thumbOff.setSize(dp(24),dp(24));
        thumb.addState(new int[]{android.R.attr.state_checked},thumbOn);thumb.addState(new int[]{},thumbOff);
        toggle.setTrackDrawable(track);toggle.setThumbDrawable(thumb);toggle.setSplitTrack(false);
        toggle.setShowText(false);toggle.setSwitchMinWidth(dp(50));toggle.setPadding(dp(8),dp(9),0,dp(9));
        row.addView(toggle,new LinearLayout.LayoutParams(dp(58),dp(48))); parent.addView(row);
        return text;
    }

    private void refresh() {
        String state = dev.graybridge.Settings.state(this);
        boolean liveVpn=dev.graybridge.Settings.prefs(this).getBoolean("vpn_active",false);
        boolean busy = dev.graybridge.Settings.busy(this);
        binding=true;
        dpiSwitch.setChecked(dev.graybridge.Settings.dpi(this)); telegramSwitch.setChecked(dev.graybridge.Settings.telegram(this));
        extrasSwitch.setChecked(dev.graybridge.Settings.extras(this));
        dpiSwitch.setEnabled(!busy); telegramSwitch.setEnabled(!busy); extrasSwitch.setEnabled(!busy); binding=false;
        String chosen = dev.graybridge.Settings.prefs(this).getString("active_strategy", "");
        profile.setText(state.equals("partial") ? "Рабочий DPI не найден" : "YouTube · Discord · " + (Strategies.auto(this) ? "Авто" : "Вручную")
            + (state.equals("on") && !chosen.isEmpty() ? " / " + chosen : ""));
        status.setText(switch(state) { case "on" -> "Включено"; case "partial" -> liveVpn?"Частичный доступ":"Только Telegram"; case "starting" -> "Подключение…"; case "stopping" -> "Выключение…"; case "error" -> "Не удалось включить"; default -> "Выключено"; });
        hint.setText(switch(state) { case "on" -> "Работает в фоне · ваш IP"; case "partial" -> liveVpn?"Дополнительные сайты включены · основной метод не найден":"Прокси включён · VPN не запущен"; case "starting" -> dev.graybridge.Settings.prefs(this).getString("probe_status", "Запускаем локальное соединение"); case "stopping" -> "Закрываем соединения"; case "error" -> "Нажмите, чтобы попробовать снова"; default -> "Нажмите, чтобы подключиться"; });
        if(extraSubtitle!=null)extraSubtitle.setText((state.equals("on") || state.equals("partial")) && dev.graybridge.Settings.extras(this) ? chatgptStatus() : "ChatGPT · Claude · Gemini · Instagram");
        if(telegramSubtitle!=null)telegramSubtitle.setText((state.equals("on") || state.equals("partial")) && dev.graybridge.Settings.telegram(this) ? telegramStatus() : "MTProto / WebSocket");
        String detail = dev.graybridge.Settings.prefs(this).getString("error","");
        if ((state.equals("on") || state.equals("partial")) && dev.graybridge.Settings.vpn(this)) detail = dev.graybridge.Settings.prefs(this).getString("probe_result", "");
        error.setText(detail); error.setVisibility((state.equals("error") || state.equals("on") || state.equals("partial")) && !detail.isEmpty() ? View.VISIBLE : View.GONE);
        if (updateSummary != null) updateSummary.setText(updateText());
        boolean telegramReady = (state.equals("on") || state.equals("partial")) && dev.graybridge.Settings.telegram(this);
        telegramButton.setEnabled(telegramReady); telegramButton.setAlpha(telegramReady?1f:.35f);
        power.on = state.equals("on") || state.equals("partial"); power.busy = state.equals("starting") || state.equals("stopping");
        power.setEnabled(!state.equals("stopping"));
        power.setContentDescription(busy ? "Выключить подключение" : "Включить подключение");
        power.invalidate();
    }

    private String telegramStatus() {
        try {
            JSONObject traffic=new JSONObject(dev.graybridge.Settings.prefs(this).getString("traffic_report","{}"));
            JSONObject check=traffic.optJSONObject("telegram_check");
            String state=check==null?"unchecked":check.optString("state","unchecked");
            return switch(state) {
                case "checking" -> "Проверяем ответ Telegram…";
                case "reachable" -> "Ответ Telegram получен";
                case "partial" -> "Ответил один из двух серверов";
                case "unavailable" -> "Нет ответа на проверку";
                default -> "Ответ Telegram ещё не проверен";
            };
        } catch(JSONException e) {return "Ответ Telegram ещё не проверен";}
    }

    private String chatgptStatus() {
        try {
            JSONObject traffic=new JSONObject(dev.graybridge.Settings.prefs(this).getString("traffic_report","{}"));
            JSONObject check=traffic.optJSONObject("chatgpt_check");
            String state=check==null?"unchecked":check.optString("state","unchecked");
            return switch(state) {
                case "checking" -> "ChatGPT: проверяем соединение…";
                case "reachable_public" -> "ChatGPT: страница отвечает";
                case "regional_refusal" -> "ChatGPT: сервис отклонил регион IP";
                case "challenge" -> "ChatGPT: требуется проверка в браузере";
                case "denied" -> "ChatGPT: сервер отказал в доступе";
                case "login_unchecked" -> "ChatGPT: требуется вход в аккаунт";
                case "transport_error" -> "ChatGPT: соединение не установлено";
                case "http_error" -> "ChatGPT: ошибка ответа сервера";
                default -> "ChatGPT: доступ ещё не проверен";
            };
        } catch(JSONException e) {return "ChatGPT: доступ ещё не проверен";}
    }

    private void connect() {
        if (connecting || dev.graybridge.Settings.busy(this)) return;
        if (!dev.graybridge.Settings.vpn(this) && !dev.graybridge.Settings.telegram(this)) { toast("Выберите сервис для подключения"); return; }
        connecting=true;
        if (Build.VERSION.SDK_INT>=33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED && !dev.graybridge.Settings.prefs(this).getBoolean("notificationAsked",false)) {
            dev.graybridge.Settings.prefs(this).edit().putBoolean("notificationAsked",true).apply();
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},101);
        } else prepareVpn();
    }
    private void prepareVpn() {
        Intent consent = dev.graybridge.Settings.vpn(this)? VpnService.prepare(this):null;
        if (consent!=null) startActivityForResult(consent,100);
        else { connecting=false; BridgeService.start(this); }
    }
    @Override public void onRequestPermissionsResult(int code,String[] permissions,int[] results) {
        super.onRequestPermissionsResult(code,permissions,results);
        if (code==101) prepareVpn();
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if (request==100) { connecting=false; if (result==RESULT_OK) BridgeService.start(this); else toast("Подключение требует разрешения VPN"); }
    }
    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent); setIntent(intent);
        AppUpdates.check(this,false);
        if (intent.getBooleanExtra("connect",false)) { intent.removeExtra("connect"); connect(); }
    }
    @Override protected void onStart() { super.onStart(); AppUpdates.check(this,false); }
    @Override protected void onResume() { super.onResume(); AppUpdates.resume(this); dev.graybridge.Settings.prefs(this).registerOnSharedPreferenceChangeListener(this); refresh(); }
    @Override protected void onPause() { dev.graybridge.Settings.prefs(this).unregisterOnSharedPreferenceChangeListener(this); super.onPause(); }
    @Override public void onSharedPreferenceChanged(SharedPreferences prefs,String key) { handler.post(this::refresh); }

    private void chooseProfile() {
        java.util.concurrent.ExecutorService task = Executors.newSingleThreadExecutor();
        task.execute(() -> {
            try {
                List<Strategies.Profile> profiles = Strategies.load(this);
                handler.post(() -> {
                    if (isFinishing() || isDestroyed() || dev.graybridge.Settings.busy(this)) return;
                    String mode = dev.graybridge.Settings.prefs(this).getString("strategy", "auto");
                    String[] names = new String[profiles.size() + 1]; names[0] = "Автоматически — проверять доступ";
                    int selected = 0;
                    for (int i=0; i<profiles.size(); i++) {
                        names[i+1] = profiles.get(i).name + (profiles.get(i).id.startsWith("adapt-") ? " · адаптация" : "");
                        if (profiles.get(i).id.equals(mode)) selected = i+1;
                    }
                    new AlertDialog.Builder(this).setTitle("Стратегия обхода DPI")
                        .setSingleChoiceItems(names, selected, (dialog,which) -> {
                            dev.graybridge.Settings.prefs(this).edit().putString("strategy", which == 0 ? "auto" : profiles.get(which-1).id).apply();
                            dialog.dismiss();
                        }).setNegativeButton("Закрыть",null).show();
                });
            } catch (Exception e) { handler.post(() -> toast("Не удалось прочитать стратегии")); }
            finally { task.shutdown(); }
        });
    }
    private void showMenu(View anchor) {
        PopupMenu popup = new PopupMenu(this,anchor);
        boolean canRetry=(dev.graybridge.Settings.state(this).equals("on") || dev.graybridge.Settings.state(this).equals("partial")) && dev.graybridge.Settings.dpi(this);
        popup.getMenu().add("Подобрать заново").setEnabled(canRetry);
        popup.getMenu().add("Расширенный подбор").setEnabled(canRetry);
        popup.getMenu().add("Мои ресурсы"); popup.getMenu().add("Обновить приложение"); popup.getMenu().add("Диагностика"); popup.getMenu().add("Обновления GitHub"); popup.getMenu().add("Работа в фоне"); popup.getMenu().add("О приложении");
        popup.setOnMenuItemClickListener(item -> {
            switch (item.getTitle().toString()) {
                case "Мои ресурсы" -> userRules();
                case "Обновить приложение" -> AppUpdates.show(this);
                case "Работа в фоне" -> battery();
                case "Обновления GitHub" -> updates();
                case "Подобрать заново" -> {
                    dev.graybridge.Settings.prefs(this).edit().putString("strategy", "auto").apply();
                    BridgeService.retest(this);
                }
                case "Расширенный подбор" -> {
                    dev.graybridge.Settings.prefs(this).edit().putString("strategy","auto").apply();
                    BridgeService.retest(this,true);
                }
                case "Диагностика" -> diagnostics();
                default -> about();
            }
            return true;
        }); popup.show();
    }
    AlertDialog userRules() {
        LinearLayout body=new LinearLayout(this);body.setOrientation(LinearLayout.VERTICAL);body.setPadding(dp(24),dp(8),dp(24),dp(12));
        TextView note=label("Домены или ссылки, по одному в строке. Правило включает поддомены. Прямые исключения имеют приоритет. Изменения применятся при следующем включении.",13,GRAY);
        body.addView(note);
        body.addView(label("Обход DPI · ваш IP",15,WHITE));
        android.widget.EditText geo=domainInput(UserRules.text(this,"geo_domains"));geo.setId(UserRules.GEO_FIELD_ID);geo.setContentDescription("Обход DPI · ваш IP");body.addView(geo);
        body.addView(label("Напрямую · без обработки DPI",15,WHITE));
        android.widget.EditText direct=domainInput(UserRules.text(this,"direct_domains"));direct.setId(UserRules.DIRECT_FIELD_ID);direct.setContentDescription("Напрямую");body.addView(direct);
        body.addView(label("Списки сохранены. Все подключения идут со своим IP; ограничения страны на стороне сервиса остаются в силе.",12,GRAY));
        ScrollView scroll=new ScrollView(this);scroll.addView(body);
        AlertDialog dialog=new AlertDialog.Builder(this).setTitle("Мои ресурсы").setView(scroll).setPositiveButton("Сохранить",null).setNegativeButton("Отмена",null).create();
        dialog.setOnShowListener(d->{
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(WHITE);dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(GRAY);
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
            String geoValue,directValue;
            try {geoValue=UserRules.parse(geo.getText().toString());}catch(IllegalArgumentException e){geo.setError(e.getMessage());return;}
            try {directValue=UserRules.parse(direct.getText().toString());}catch(IllegalArgumentException e){direct.setError(e.getMessage());return;}
            dev.graybridge.Settings.prefs(this).edit().putString("geo_domains",geoValue).putString("direct_domains",directValue).apply();
            dialog.dismiss();toast("Сохранено. Применится при следующем включении.");refresh();
        });});dialog.show();return dialog;
    }
    private android.widget.EditText domainInput(String value) {
        android.widget.EditText input=new android.widget.EditText(this);input.setText(value);input.setTextSize(14);input.setTextColor(WHITE);
        input.setHint("example.com\nhttps://service.example.org");input.setHintTextColor(GRAY);input.setMinLines(3);input.setMaxLines(5);
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT|android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE|android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        input.setGravity(Gravity.TOP);input.setFilters(new android.text.InputFilter[]{new android.text.InputFilter.LengthFilter(UserRules.MAX_TEXT)});
        return input;
    }
    private String diagnosticText() {
        try {
            SharedPreferences prefs=dev.graybridge.Settings.prefs(this);
            JSONObject report=new JSONObject();
            report.put("version",BuildConfig.VERSION_NAME).put("device",Build.MANUFACTURER+" "+Build.MODEL)
                .put("reconnect_count",prefs.getInt("reconnect_count",0)).put("network_reconnect_count",prefs.getInt("network_reconnect_count",0))
                .put("custom_geo_count",UserRules.domains(this,"geo_domains").length()).put("custom_direct_count",UserRules.domains(this,"direct_domains").length())
                .put("android",Build.VERSION.RELEASE).put("sdk",Build.VERSION.SDK_INT)
                .put("state",dev.graybridge.Settings.state(this)).put("strategy",prefs.getString("active_strategy",""))
                .put("extra_sites",dev.graybridge.Settings.extras(this)).put("own_ip",true)
                .put("checks",new JSONArray(prefs.getString("probe_report","[]")))
                .put("traffic",new JSONObject(prefs.getString("traffic_report","{}")))
                .put("network",new JSONObject(prefs.getString("network_report","{}")))
                .put("private_dns_mode",Settings.Global.getString(getContentResolver(),"private_dns_mode"))
                .put("native_exit",prefs.contains("native_exit")?prefs.getInt("native_exit",0):JSONObject.NULL);
            if(dev.graybridge.Settings.state(this).equals("on") && dev.graybridge.Settings.vpn(this)) {
                long[] stats=NativeTunnel.stats();
                report.put("tun",new JSONObject().put("tx_packets",stats[0]).put("tx_bytes",stats[1])
                    .put("rx_packets",stats[2]).put("rx_bytes",stats[3]));
            }
            return report.toString(2);
        } catch(Exception | LinkageError e) { return "Не удалось сформировать диагностику: "+e.getClass().getSimpleName(); }
    }
    private void diagnostics() {
        String text=diagnosticText();
        ScrollView scroll=new ScrollView(this); TextView body=label(text,11,GRAY);
        body.setPadding(dp(20),dp(12),dp(20),dp(12)); body.setTextIsSelectable(true); scroll.addView(body);
        new AlertDialog.Builder(this).setTitle("Диагностика").setView(scroll).setPositiveButton("Закрыть",null)
            .setNeutralButton("Копировать",(d,w)-> {
                ((ClipboardManager)getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("SorryRKN diagnostics",text));
                toast("Диагностика скопирована");
            }).show();
    }
    private String updateText() {
        long checked = dev.graybridge.Settings.prefs(this).getLong("update_checked", 0);
        return dev.graybridge.Settings.prefs(this).getString("update_status", "Используются данные из APK")
            + (checked > 0 ? "\n\nПроверено: " + DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date(checked)) : "")
            + "\n\nСписки сайтов, исключения, домены Telegram и совместимые параметры стратегий обновляются с GitHub. Новые функции движка требуют обновления APK. Windows ALT адаптируются только в поддерживаемой части.";
    }
    private void updates() {
        LinearLayout body = new LinearLayout(this); body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(24),dp(12),dp(24),dp(12));
        updateSummary = label(updateText(),13,GRAY); body.addView(updateSummary);
        Switch automatic = new Switch(this); automatic.setText("Автоматически, раз в сутки");
        automatic.setTextSize(13); automatic.setTextColor(WHITE); automatic.setPadding(0,dp(20),0,0);
        automatic.setChecked(dev.graybridge.Settings.prefs(this).getBoolean("auto_updates",true));
        automatic.setOnCheckedChangeListener((v,on) -> {
            dev.graybridge.Settings.prefs(this).edit().putBoolean("auto_updates",on).apply();
            DataUpdates.schedule(this); if (on) DataUpdates.request(this,false);
        }); body.addView(automatic);
        ScrollView scroll = new ScrollView(this); scroll.addView(body);
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("Обновления GitHub").setView(scroll)
            .setPositiveButton("Закрыть",null).setNeutralButton("Проверить сейчас",null).create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> {
            DataUpdates.request(this,true); toast("Проверяем обновления");
        }));
        dialog.setOnDismissListener(d -> updateSummary=null); dialog.show();
    }
    private void addTile() {
        if (Build.VERSION.SDK_INT>=33) {
            getSystemService(StatusBarManager.class).requestAddTileService(new ComponentName(this,BridgeTile.class),"SorryRKN",Icon.createWithResource(this,R.drawable.ic_bridge),getMainExecutor(),result -> {
                if (result==StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_NOT_ADDED) toast("Можно добавить SorryRKN через редактирование шторки");
            });
        } else new AlertDialog.Builder(this).setTitle("Быстрые настройки").setMessage("Откройте шторку → редактирование плиток → перетащите SorryRKN к Wi-Fi и Bluetooth.").setPositiveButton("Понятно",null).show();
    }
    private void battery() {
        PowerManager pm = getSystemService(PowerManager.class);
        if (pm.isIgnoringBatteryOptimizations(getPackageName())) { toast("Фоновая работа уже разрешена"); return; }
        new AlertDialog.Builder(this).setTitle("Работа в фоне").setMessage("Разрешите работу без ограничений батареи, чтобы Android реже останавливал подключение при выключенном экране.")
            .setPositiveButton("Открыть настройки",(d,w) -> {
                try { startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)); }
                catch(ActivityNotFoundException e) { startActivity(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:"+getPackageName()))); }
            }).setNegativeButton("Позже",null).show();
    }
    private void about() {
        new AlertDialog.Builder(this).setTitle("SorryRKN " + BuildConfig.VERSION_NAME)
            .setMessage("Локальный обход DPI и Telegram-прокси. Android показывает значок VPN для перехвата трафика на устройстве. Внешний VPN-сервер не используется: соединения идут со своим IP. Telegram подключается к серверам Telegram, публичные промежуточные прокси отключены.\n\nБыстрый подбор проверяет основные методы и сохранённый вариант; полный каталог доступен через «Расширенный подбор». Проверяются DNS по HTTPS, ответ YouTube и Discord API, WebSocket Hello для чатов, PNG с CDN. Видеопотоки, авторизация и голос этим тестом не проверяются. Успешная проверка YouTube сохраняет VPN, даже если Discord не прошёл все проверки. Если оба сервиса недоступны, остаётся только Telegram-прокси. Результаты и счётчики VPN доступны в «Диагностике».\n\nByeDPI также пробует другие методы для отдельных соединений при таймауте, сбросе или ошибке TLS. Обход DPI зависит от оператора. UDP передаётся без изменения; обход блокировки голоса Discord не гарантируется. Одновременно Android поддерживает один VPN.\n\nПрокси Telegram: 127.0.0.1:1443. Секрет хранится на устройстве.\n\nЭто независимое приложение, не официальный продукт Flowseal или ByeDPIAndroid.")
            .setPositiveButton("Закрыть",null).setNeutralButton("Лицензии",(d,w) -> licenses()).show();
    }
    private void licenses() {
        StringBuilder text = new StringBuilder();
        try {
            for(String name:getAssets().list("licenses")) {
                text.append(name).append("\n\n");
                try(InputStream in=getAssets().open("licenses/"+name); ByteArrayOutputStream out=new ByteArrayOutputStream()) {
                    byte[] buf=new byte[8192]; int count; while((count=in.read(buf))>=0) out.write(buf,0,count);
                    text.append(new String(out.toByteArray(),StandardCharsets.UTF_8)).append("\n\n");
                }
            }
        } catch(IOException e) { text.append("Не удалось прочитать лицензии"); }
        ScrollView scroll=new ScrollView(this); TextView body=label(text.toString(),11,GRAY); body.setPadding(dp(20),dp(12),dp(20),dp(12)); scroll.addView(body);
        new AlertDialog.Builder(this).setTitle("Открытые компоненты").setView(scroll).setPositiveButton("Закрыть",null).show();
    }
    private void copyProxy() { ((ClipboardManager)getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("Telegram proxy",dev.graybridge.Settings.link(this))); }
    private void toast(String text) { Toast.makeText(this,text,Toast.LENGTH_SHORT).show(); }
    private TextView label(String text,int size,int color) { TextView view=new TextView(this); view.setText(text); view.setTextSize(size); view.setTextColor(color); view.setFontFeatureSettings("kern"); return view; }
    private GradientDrawable shape(int fill,int radius,int stroke) { GradientDrawable d=new GradientDrawable(); d.setColor(fill); d.setCornerRadius(radius); d.setStroke(dp(1),stroke); return d; }
    private int dp(float value) { return Math.round(value*getResources().getDisplayMetrics().density); }

    private class PowerView extends View {
        boolean on,busy;
        final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
        PowerView() { super(MainActivity.this); setClickable(true); setFocusable(true); }
        @Override protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            float cx=getWidth()/2f,cy=getHeight()/2f,r=getWidth()/2f-dp(8);
            paint.setStyle(Paint.Style.STROKE); paint.setStrokeWidth(dp(1)); paint.setColor(BORDER);
            canvas.drawCircle(cx,cy,r+dp(7),paint);
            paint.setStyle(Paint.Style.FILL); paint.setColor(on?WHITE:PANEL); canvas.drawCircle(cx,cy,r,paint);
            if(busy) {
                paint.setStyle(Paint.Style.STROKE); paint.setStrokeWidth(dp(2)); paint.setColor(GRAY);
                float angle=(SystemClock.uptimeMillis()%1500)*360f/1500;
                canvas.drawArc(cx-r-dp(7),cy-r-dp(7),cx+r+dp(7),cy+r+dp(7),angle,75,false,paint);
                postInvalidateDelayed(32);
            }
            Drawable mark=getDrawable(R.drawable.ic_bridge).mutate();
            mark.setTint(on?BG:WHITE);
            int half=dp(37);mark.setBounds((int)cx-half,(int)cy-half,(int)cx+half,(int)cy+half);mark.draw(canvas);
        }
        @Override public boolean onTouchEvent(android.view.MotionEvent event) {
            if(event.getAction()==MotionEvent.ACTION_DOWN) animate().scaleX(.96f).scaleY(.96f).setDuration(100).start();
            if(event.getAction()==MotionEvent.ACTION_UP||event.getAction()==MotionEvent.ACTION_CANCEL) animate().scaleX(1).scaleY(1).setDuration(140).start();
            return super.onTouchEvent(event);
        }
        @Override public boolean performClick() { return super.performClick(); }
    }
}
