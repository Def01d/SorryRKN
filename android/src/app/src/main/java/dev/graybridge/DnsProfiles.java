package dev.graybridge;

import android.app.*;
import android.content.*;
import android.graphics.Typeface;
import android.os.*;
import android.widget.*;
import com.chaquo.python.Python;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.*;
import android.net.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

/** DNS comparisons own anonymous connections and never change the saved choice. */
final class DnsProfiles {
    private static final ExecutorService WORK = Executors.newFixedThreadPool(2);
    private static final AtomicBoolean BUSY = new AtomicBoolean();
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static long lastAttempt;
    private static String lastNetwork="";

    static String networkKey(Context context) {
        try {
            ConnectivityManager cm=context.getSystemService(ConnectivityManager.class);
            Network network=cm.getActiveNetwork();
            // Prefer the underlying physical network when our local VPN is active.
            for(Network n:cm.getAllNetworks()) {
                NetworkCapabilities caps=cm.getNetworkCapabilities(n);
                if(caps!=null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                    if(network==null || !Objects.equals(network,n))network=n;
                    NetworkInfo info=cm.getNetworkInfo(n);if(info!=null && info.isConnected())break;
                }
            }
            if(network==null)return "offline";
            String value=network.toString()+"/"+cm.getLinkProperties(network);
            byte[] hash=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder out=new StringBuilder();for(int i=0;i<16;i++)out.append(String.format(Locale.ROOT,"%02x",hash[i]));
            return out.toString();
        } catch(Exception ignored){return "unknown";}
    }

    static void check(Context context, boolean force) {
        Context app = context.getApplicationContext();
        String network=networkKey(app);
        if (!force && (!Settings.aiRelay(app) || !Settings.prefs(app).getBoolean("dns_check_startup", true)
                || SystemClock.elapsedRealtime()-lastAttempt<300000 && lastAttempt!=0 && network.equals(lastNetwork))) return;
        if (!BUSY.compareAndSet(false,true)) return;
        lastAttempt=SystemClock.elapsedRealtime();
        lastNetwork=network;
        Settings.prefs(app).edit().putString("dns_scan_status","Проверяем DNS и восемь сервисов…").apply();
        WORK.execute(()->{
            try {
                DataUpdates.module(app);
                JSONObject selected=new JSONObject().put("default",Settings.prefs(app).getString("dns_profile","comss"))
                    .put("services",new JSONObject(Settings.prefs(app).getString("service_dns","{}")));
                String result=Python.getInstance().getModule("dns_matrix").callAttr("scan_json",
                    app.getFilesDir().getPath(),Settings.prefs(app).getBoolean("auto_updates",true),force,selected.toString(),network).toString();
                if(!network.equals(networkKey(app)))throw new IllegalStateException("Network changed");
                new JSONObject(result);
                Settings.prefs(app).edit().putString("dns_scan_report",result)
                    .putString("dns_scan_status","Проверка завершена").apply();
            } catch(Exception e) {
                Settings.prefs(app).edit().putString("dns_scan_status","Проверка не завершена. Повторите позже.").apply();
            } finally {BUSY.set(false);}
        });
    }

    static String stateLabel(String state) {
        return switch(state) {
            case "reachable_public" -> "Страница доступна";
            case "login_unchecked" -> "Вход не проверен";
            case "regional_refusal" -> "Отказ по региону";
            case "challenge" -> "Проверка браузера";
            case "denied" -> "Отказ HTTP 403";
            case "rate_limited" -> "Лимит запросов";
            case "dns_error" -> "DNS не ответил";
            case "timeout" -> "Тайм-аут";
            case "transport_error" -> "Ошибка соединения";
            case "invalid_response" -> "Ответ не подтверждён";
            case "http_error" -> "Ошибка HTTP";
            default -> "Не проверено";
        };
    }

    static AlertDialog show(Activity activity) {
        LinearLayout body=new LinearLayout(activity);body.setOrientation(LinearLayout.VERTICAL);
        int pad=(int)(20*activity.getResources().getDisplayMetrics().density);body.setPadding(pad,pad,pad,pad);
        TextView note=new TextView(activity);
        note.setText("Выберите DNS по результатам HTTPS-проверок в вашей сети. Для сравнения отправляются отдельные публичные запросы через каждый профиль; аккаунты и отправка сообщений не проверяются. Проверки не меняют DNS. Сохранённый профиль применяется при следующем включении соединения.");
        body.addView(note);
        Button services=new Button(activity);services.setText("Маршруты сервисов");body.addView(services);
        services.setOnClickListener(v->ServiceRoutes.show(activity));
        Spinner picker=new Spinner(activity);picker.setEnabled(false);body.addView(picker);
        ArrayList<String> ids=new ArrayList<>();ArrayList<String> names=new ArrayList<>();
        ids.add("comss");names.add("Comss");
        ArrayAdapter<String> adapter=new ArrayAdapter<>(activity,android.R.layout.simple_spinner_dropdown_item,names);
        picker.setAdapter(adapter);
        String selected=Settings.prefs(activity).getString("dns_profile","comss");
        final JSONArray[] definitions=new JSONArray[1];
        WORK.execute(()->{
            try {
                DataUpdates.module(activity.getApplicationContext());
                JSONObject catalog=new JSONObject(Python.getInstance().getModule("dns_matrix").callAttr("catalog_json",activity.getFilesDir().getPath()).toString());
                JSONArray serviceList=new JSONArray(Python.getInstance().getModule("service_catalog").callAttr("services_json").toString());
                MAIN.post(()->{
                    if(activity.isFinishing() || activity.isDestroyed())return;
                    ids.clear();names.clear();JSONArray profiles=catalog.optJSONArray("profiles");
                    definitions[0]=serviceList;
                    if(profiles!=null)for(int i=0;i<profiles.length();i++) {
                        JSONObject p=profiles.optJSONObject(i);if(p!=null){ids.add(p.optString("id"));names.add(p.optString("name"));}
                    }
                    adapter.notifyDataSetChanged();int index=ids.indexOf(selected);picker.setSelection(Math.max(0,index));picker.setEnabled(true);
                });
            } catch(Exception ignored) {}
        });
        CheckBox auto=new CheckBox(activity);auto.setText("Проверять при открытии приложения");
        auto.setChecked(Settings.prefs(activity).getBoolean("dns_check_startup",true));
        auto.setOnCheckedChangeListener((b,value)->Settings.prefs(activity).edit().putBoolean("dns_check_startup",value).apply());body.addView(auto);
        CheckBox full=new CheckBox(activity);full.setText("Показать всю матрицу DNS");body.addView(full);
        TextView results=new TextView(activity);results.setTextIsSelectable(true);results.setTypeface(Typeface.MONOSPACE);body.addView(results);
        ScrollView scroll=new ScrollView(activity);scroll.addView(body);
        AlertDialog dialog=new AlertDialog.Builder(activity).setTitle("DNS и нейросети").setView(scroll)
            .setPositiveButton("Сохранить DNS",null).setNeutralButton("Проверить",null).setNegativeButton("Закрыть",null).create();
        Runnable refresh=new Runnable(){ public void run(){
            if(!dialog.isShowing())return;
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(picker.isEnabled());
            StringBuilder text=new StringBuilder(Settings.prefs(activity).getString("dns_scan_status","Ещё не проверено"));
            text.append("\nВыбран: ").append(Settings.prefs(activity).getString("dns_profile","comss"));
            if(!Settings.aiRelay(activity))text.append("\nРеле выключено: автопроверка приостановлена. Кнопка «Проверить» сравнит реле отдельными запросами.");
            try {
                JSONObject report=new JSONObject(Settings.prefs(activity).getString("dns_scan_report","{}"));
                text.append("\n").append(report.optString("checked_at",""));
                text.append(report.optBoolean("cached")?" · из кеша":"");
                text.append("full".equals(report.optString("coverage"))?"\nПолное сравнение":"\nПроверены выбранные маршруты; полный перебор — кнопка «Проверить»");
                if(!networkKey(activity).equals(report.optString("network_key")))text.append("\nРезультаты относятся к другой сети");
                JSONArray profiles=report.optJSONArray("profiles");
                if(!full.isChecked())text.append(RouteSummary.text(activity,report,definitions[0]));
                if(full.isChecked() && profiles!=null)for(int i=0;i<profiles.length();i++) {
                    JSONObject p=profiles.getJSONObject(i);text.append("\n\n").append(p.optString("name"));
                    JSONArray cells=p.getJSONArray("results");
                    for(int j=0;j<cells.length();j++) {
                        JSONObject cell=cells.getJSONObject(j);text.append("\n").append(cell.optString("name")).append(": ").append(stateLabel(cell.optString("state")));
                        if(cell.has("http_status"))text.append(" · ").append(cell.optInt("http_status"));
                        if(cell.has("latency_ms"))text.append(" · ").append(cell.optLong("latency_ms")).append(" мс");
                    }
                }
            } catch(JSONException ignored) {}
            String value=text.toString();if(!results.getText().toString().equals(value))results.setText(value);
            MAIN.postDelayed(this,700);
        }};
        dialog.setOnShowListener(d->{
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v->check(activity,true));
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
                if(picker.getSelectedItemPosition()>=0 && picker.getSelectedItemPosition()<ids.size()) {
                    Settings.prefs(activity).edit().putString("dns_profile",ids.get(picker.getSelectedItemPosition())).apply();
                    Toast.makeText(activity,"DNS сохранён. Применится при следующем включении соединения.",Toast.LENGTH_LONG).show();
                    dialog.dismiss();
                }
            });refresh.run();
        });
        dialog.setOnDismissListener(d->MAIN.removeCallbacks(refresh));dialog.show();return dialog;
    }
}
