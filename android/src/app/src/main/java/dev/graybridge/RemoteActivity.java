package dev.graybridge;

import android.app.*;
import android.content.*;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.*;
import android.text.InputType;
import android.view.*;
import android.widget.*;
import org.json.*;
import java.io.*;
import java.util.concurrent.*;

public class RemoteActivity extends Activity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final ExecutorService WORK=Executors.newSingleThreadExecutor();
    private static final int BG=0xff0b0b0c, CARD=0xff19191c, FG=0xffeeeeef, MUTED=0xffaaaab2;
    private LinearLayout page;
    private TextView note;
    private boolean working;
    private String message="";
    private byte[] identity;
    private String pendingTitle,pendingAction;
    private String mode() { return Settings.prefs(this).getString("remote_mode","server"); }
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().setStatusBarColor(BG); getWindow().setNavigationBarColor(BG);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        ScrollView scroll=new ScrollView(this); scroll.setBackgroundColor(BG);
        scroll.setOnApplyWindowInsetsListener((v,insets)->{
            v.setPadding(insets.getSystemWindowInsetLeft(),insets.getSystemWindowInsetTop(),insets.getSystemWindowInsetRight(),insets.getSystemWindowInsetBottom());
            return insets;
        });
        page=new LinearLayout(this); page.setOrientation(LinearLayout.VERTICAL); page.setPadding(dp(24),dp(24),dp(24),dp(20));
        scroll.addView(page); setContentView(scroll); draw();
    }
    @Override protected void onStart() { super.onStart(); AppUpdates.check(this,false); }
    @Override protected void onResume() { super.onResume(); AppUpdates.resume(this); Settings.prefs(this).registerOnSharedPreferenceChangeListener(this); draw(); }
    @Override protected void onPause() { Settings.prefs(this).unregisterOnSharedPreferenceChangeListener(this); super.onPause(); }
    @Override public void onSharedPreferenceChanged(SharedPreferences p,String key) { if(key.equals("remote_state") || key.equals("remote_error")) draw(); }
    private int dp(int n){return Math.round(getResources().getDisplayMetrics().density*n);}
    private TextView text(String s,int size,int color) {
        TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(color);page.addView(t);return t;
    }
    private void action(String title,Runnable click,boolean enabled) {
        TextView b=text(title,16,FG); b.setPadding(dp(16),dp(14),dp(16),dp(14));
        LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,-2);lp.topMargin=dp(8);b.setLayoutParams(lp);
        GradientDrawable bg=new GradientDrawable();bg.setColor(CARD);bg.setCornerRadius(dp(12));b.setBackground(bg);
        b.setAlpha(enabled?1f:.4f);b.setEnabled(enabled);b.setOnClickListener(v->click.run());
    }
    private void draw() {
        page.removeAllViews();
        boolean server=mode().equals("server"), busy=RemoteVpnService.busy(this);
        boolean editable=!busy && !working && !Settings.busy(this);
        action("←  Локальный обход",()->{
            Settings.prefs(this).edit().putBoolean("remote_home",false).apply();
            startActivity(new Intent(this,MainActivity.class));finish();
        },editable);
        TextView heading=text(server?"Свой сервер":"Подписки",30,FG);
        heading.setTypeface(Typeface.DEFAULT,Typeface.BOLD);heading.setPadding(0,dp(24),0,dp(6));
        text(server?"HTTPS · управление Linux по SSH":"Xray · выбранный узел для приложений",14,MUTED);
        String state=RemoteVpnService.status(this);
        String status=switch(state) { case "on"->"Туннель включён"; case "starting"->"Подключение…"; case "stopping"->"Отключение…"; case "error"->"Ошибка"; default->"Выключено"; };
        TextView current=text(status,20,FG);current.setPadding(0,dp(24),0,dp(6));
        try {
            if(server) {
                JSONObject profile=RemoteVault.read(this,"server");
                text(profile.optString("host","Настройте HTTPS на Linux-сервере"),14,MUTED);
                if(profile.has("https"))text(NaiveEngine.relay(profile.getString("https"))!=null?
                    "HTTPS · TCP и UDP":"Старый HTTPS-профиль · только TCP. Обновите настройку HTTPS через SSH.",13,MUTED);
                action(busy?"Отключить":"Подключить",this::toggle,!working && !Settings.busy(this) && (state.equals("on") || !busy && profile.has("https")));
                action("Управление по SSH",this::serverMenu,editable);
                if(SshForward.port()>0) action("Отключить локальный SOCKS5",()->{SshForward.stop(this);message="SSH-переадресация отключена";draw();},!working);
            } else {
                JSONObject book=RemoteSubscriptions.library(this);
                JSONArray groups=book.getJSONArray("groups");
                JSONObject group=groups.length()>0?RemoteSubscriptions.selected(book):null;
                if(group!=null) {
                    String name=group.getJSONArray("nodes").getJSONObject(group.optInt("index")).getString("name");
                    text(group.getString("name")+" · "+name,14,MUTED);
                }
                action(busy?"Отключить":"Подключить",this::toggle,!working && !Settings.busy(this) && (state.equals("on") || !busy && group!=null));
                action("Добавить подписку или узел",this::addSubscription,editable);
                if(group!=null) {
                    action("Выбрать подписку и узел",this::chooseGroup,editable);
                    if(!group.optString("url").isEmpty()) action("Обновить список узлов",()->loadSubscription(group.optString("url"),true),editable);
                    action("Удалить подписку",this::removeGroup,editable);
                }
            }
        } catch(Exception e) { text("Не удалось прочитать защищённый профиль.",14,MUTED); }
        action(server?"Перейти к подпискам":"Перейти к своему серверу",()->{
            Settings.prefs(this).edit().putString("remote_mode",server?"subscriptions":"server").apply();message="";draw();
        },editable);
        note=text(working?"Выполняется операция…":message.isEmpty()?Settings.prefs(this).getString("remote_error",""):message,13,MUTED);
        note.setPadding(0,dp(16),0,0);
    }
    private void toggle() {
        if(RemoteVpnService.status(this).equals("on")) {
            RemoteVpnService.stop(this);
            return;
        }
        Intent consent=VpnService.prepare(this);
        if(consent!=null) startActivityForResult(consent,42); else startTunnel();
    }
    private void startTunnel() {
        if(Settings.busy(this) || RemoteVpnService.busy(this)) return;
        RemoteVpnService.start(this);
    }
    @Override protected void onActivityResult(int code,int result,Intent data) {
        super.onActivityResult(code,result,data);
        if(code==42 && result==RESULT_OK) startTunnel();
        if(code==44 && result==RESULT_OK && data!=null && data.getData()!=null) {
            try(InputStream stream=getContentResolver().openInputStream(data.getData().normalizeScheme()); ByteArrayOutputStream buf=new ByteArrayOutputStream()){
                if(stream==null)throw new IOException();byte[] bytes=new byte[4096];int n;
                while((n=stream.read(bytes))!=-1){if(buf.size()+n>131072)throw new IOException();buf.write(bytes,0,n);}
                byte[] key=buf.toByteArray();if(!new String(key,0,Math.min(key.length,100),java.nio.charset.StandardCharsets.US_ASCII).contains("PRIVATE KEY-----"))throw new IOException();
                identity=key;
                if(pendingAction!=null)sshForm(pendingTitle,pendingAction);
            }catch(Exception e){message="Не удалось прочитать SSH-ключ";draw();}
        }
    }
    private void run(Callable<String> work) {
        if(working)return;working=true;message="";draw();
        WORK.execute(()->{
            String result;
            try {result=work.call();} catch(Exception e){result=e instanceof IOException && e.getMessage()!=null?e.getMessage():"Не удалось выполнить операцию. Проверьте формат и подключение.";}
            String value=result;runOnUiThread(()->{if(isFinishing()||isDestroyed())return;working=false;message=value;draw();});
        });
    }
    private void addSubscription() {
        EditText input=new EditText(this);input.setHint("HTTPS-ссылка или ссылка узла");input.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        new AlertDialog.Builder(this).setTitle("Новая подписка").setView(input)
            .setPositiveButton("Добавить",(d,w)->loadSubscription(input.getText().toString(),false)).setNegativeButton("Отмена",null).show();
    }
    private void loadSubscription(String source,boolean refresh){run(()->RemoteSubscriptions.update(this,source,refresh));}
    private void chooseGroup() {
        try {
            JSONObject book=RemoteSubscriptions.library(this); JSONArray groups=book.getJSONArray("groups"); String[] titles=new String[groups.length()];
            for(int i=0;i<titles.length;i++) titles[i]=groups.getJSONObject(i).getString("name");
            new AlertDialog.Builder(this).setTitle("Подписки").setItems(titles,(d,index)->{
                try {
                    JSONObject group=groups.getJSONObject(index); JSONArray nodes=group.getJSONArray("nodes"); String[] names=new String[nodes.length()];
                    for(int i=0;i<names.length;i++) names[i]=nodes.getJSONObject(i).getString("name");
                    new AlertDialog.Builder(this).setTitle(titles[index]).setSingleChoiceItems(names,group.optInt("index"),(dialog,n)->{
                        dialog.dismiss();run(()->{group.put("index",n);book.put("selected",index);RemoteVault.write(this,"subscriptions",book);return "";});
                    }).setNegativeButton("Отмена",null).show();
                }catch(Exception e){message="Не удалось прочитать узлы";draw();}
            }).show();
        } catch(Exception e){message="Не удалось прочитать библиотеку";draw();}
    }
    private void removeGroup() {
        new AlertDialog.Builder(this).setTitle("Удалить выбранную подписку?").setPositiveButton("Удалить",(d,w)->run(()->{
            JSONObject book=RemoteSubscriptions.library(this); book.getJSONArray("groups").remove(book.optInt("selected"));
            book.put("selected",0);RemoteVault.write(this,"subscriptions",book);return "";
        })).setNegativeButton("Отмена",null).show();
    }
    private void serverMenu() {
        String[] titles={"Настроить HTTPS","Состояние HTTPS и SOCKS5","Запустить HTTPS","Остановить HTTPS","Включить SOCKS5 через SSH","Остановить SOCKS5","Настроить VLESS / REALITY","Получить узел REALITY","Состояние REALITY","Остановить REALITY","Показать данные SOCKS5"};
        String[] actions={"https-on","https-status","https-start","https-off","install-socks","stop-socks","reality-on","reality-profile","reality-status","reality-off"};
        new AlertDialog.Builder(this).setTitle("Управление сервером").setItems(titles,(d,i)->{
            if(i==actions.length) {
                try { String socks=SshForward.port()>0?"127.0.0.1:"+SshForward.port()+"\n"+RemoteVault.read(this,"server").optString("socks"):"Подключите SOCKS5 через SSH.";
                    new AlertDialog.Builder(this).setTitle("Локальный SOCKS5").setMessage(socks).setPositiveButton("Закрыть",null).show();
                } catch(Exception e){message="Не удалось прочитать данные SOCKS5";draw();}
            } else sshForm(titles[i],actions[i]);
        }).show();
    }
    private EditText field(LinearLayout form,String hint,String value,int type) {
        EditText input=new EditText(this); input.setSingleLine();input.setHint(hint);input.setText(value);input.setInputType(type);
        input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);form.addView(input);return input;
    }
    private void sshForm(String title,String action) {
        try {
            JSONObject previous=RemoteVault.read(this,"server");
            LinearLayout form=new LinearLayout(this);form.setPadding(dp(18),0,dp(18),0);form.setOrientation(LinearLayout.VERTICAL);
            TextView help=new TextView(this);help.setText("Debian / Ubuntu, root либо sudo без пароля. "+(identity==null?"Вход по паролю.":"Выбран SSH-ключ."));form.addView(help);
            EditText host=field(form,"Адрес сервера",previous.optString("host"),InputType.TYPE_CLASS_TEXT);
            EditText port=field(form,"Порт",String.valueOf(previous.optInt("port",22)),InputType.TYPE_CLASS_NUMBER);
            EditText user=field(form,"Пользователь",previous.optString("user","root"),InputType.TYPE_CLASS_TEXT);
            EditText pass=field(form,identity==null?"Пароль SSH":"Пароль ключа (если есть)","",InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);
            new AlertDialog.Builder(this).setTitle(title).setView(form).setPositiveButton("Выполнить",(d,w)->{
                try {
                    String h=ServerSSH.host(host.getText().toString()); int p=Integer.parseInt(port.getText().toString());
                    boolean same=h.equals(previous.optString("host"))&&p==previous.optInt("port");
                    JSONObject profile=same?previous:new JSONObject();
                    profile.put("host",h).put("port",p).put("user",user.getText().toString());
                    ssh(profile,pass.getText().toString(),action);
                }catch(Exception e){message="Проверьте адрес и порт.";draw();}
            }).setNegativeButton("Отмена",null).setNeutralButton(identity==null?"SSH-ключ":"По паролю",(d,w)->{
                if(identity!=null){java.util.Arrays.fill(identity,(byte)0);identity=null;sshForm(title,action);return;}
                pendingAction=action;pendingTitle=title;
                startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"),44);
            }).show();
        }catch(Exception e){message="Не удалось прочитать сервер";draw();}
    }
    private void ssh(JSONObject profile,String password,String action) {
        run(()->{
            try {
                String record=ServerSSH.run(this,profile,password,action,identity);
                String result=ServerSSH.apply(profile,record);
                if(record.startsWith("SRKN1\tREALITY\t")) RemoteSubscriptions.update(this,profile.getString("reality"),false);
                RemoteVault.write(this,"server",profile);
                return result;
            } catch(ServerSSH.Untrusted first) {
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
                    new AlertDialog.Builder(this).setTitle("Ключ SSH сервера").setMessage(profile.optString("host")+"\n"+first.fingerprint+"\n\nСверьте отпечаток с консолью VPS. После подтверждения ключ будет закреплён.")
                        .setNegativeButton("Отмена",null).setPositiveButton("Ключ совпадает",(d,w)->{
                            try { profile.put("pin",first.fingerprint);ssh(profile,password,action); }
                            catch(Exception e){message="Не удалось сохранить отпечаток";draw();}
                        }).show();
                });
                return "";
            }
        });
    }
}
