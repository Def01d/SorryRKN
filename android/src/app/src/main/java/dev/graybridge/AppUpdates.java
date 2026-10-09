package dev.graybridge;

import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.net.Uri;
import android.os.*;
import android.widget.Toast;
import org.json.JSONObject;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.lang.ref.WeakReference;

/** APK releases are separate from upstream declarative data updates. */
final class AppUpdates {
    static final String SOURCE="https://raw.githubusercontent.com/Def01d/SorryRKN/main/update.json";
    private static final ExecutorService WORK=Executors.newSingleThreadExecutor();
    private static final Handler MAIN=new Handler(Looper.getMainLooper());
    private static boolean checking, downloading;
    private static WeakReference<Activity> checkTarget;
    private static boolean checkForce;
    static final long MAX_APK=64L*1024*1024;
    static final class Release {
        final int code; final String name, url, sha, notes; final long size;
        Release(JSONObject j) throws Exception {
            code=j.getInt("versionCode"); name=j.getString("versionName"); url=j.getString("url");
            sha=j.getString("sha256").toLowerCase(Locale.ROOT); size=j.getLong("size"); notes=j.optString("notes","");
            if(code<=0 || name.length()>40 || notes.length()>4000 || !sha.matches("[0-9a-f]{64}") || size<=0 || size>MAX_APK)
                throw new IOException("Некорректный манифест обновления");
            safeUrl(url);
        }
    }
    static URL safeUrl(String value) throws Exception {
        URL u=new URL(value);
        if(!u.getProtocol().equals("https") || u.getUserInfo()!=null || u.getHost().isEmpty()) throw new IOException("Требуется HTTPS");
        return u;
    }
    static void show(Activity activity) {
        String source=Settings.prefs(activity).getString("apk_update_url",SOURCE);
        new AlertDialog.Builder(activity).setTitle("Обновления SorryRKN")
            .setMessage("Новые версии APK предлагаются при запуске. Для установки Android запросит подтверждение.\n\nИсточник:\n"+source)
            .setPositiveButton("Проверить",(d,w)->check(activity,true))
            .setNegativeButton("Закрыть",null).setNeutralButton("Источник",(d,w)->{
                android.widget.EditText input=new android.widget.EditText(activity);
                input.setSingleLine(true);input.setText(source);input.setInputType(android.text.InputType.TYPE_CLASS_TEXT|android.text.InputType.TYPE_TEXT_VARIATION_URI);
                AlertDialog dialog=new AlertDialog.Builder(activity).setTitle("HTTPS-ссылка на update.json").setView(input)
                    .setPositiveButton("Сохранить",null).setNegativeButton("Отмена",null).create();
                dialog.setOnShowListener(x->dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
                    try {String value=input.getText().toString().trim();safeUrl(value);
                        Settings.prefs(activity).edit().putString("apk_update_url",value).remove("apk_update_checked").apply();dialog.dismiss();check(activity,true);
                    }catch(Exception e){input.setError("Нужна HTTPS-ссылка без пароля");}
                }));dialog.show();
            }).show();
    }
    static void check(Activity activity, boolean force) {
        checkTarget=new WeakReference<>(activity);
        checkForce=checking ? checkForce||force : force;
        if(checking) return;
        checking=true;
        Context context=activity.getApplicationContext();
        String source=Settings.prefs(context).getString("apk_update_url",SOURCE);
        WORK.execute(()->{
            try {
                Release release;
                try(InputStream in=open(source,true)) {
                    ByteArrayOutputStream out=new ByteArrayOutputStream(); byte[] b=new byte[4096]; int n;
                    while((n=in.read(b))!=-1) { if(out.size()+n>16384) throw new IOException("Манифест слишком большой"); out.write(b,0,n); }
                    release=new Release(new JSONObject(out.toString(StandardCharsets.UTF_8.name())));
                }
                Settings.prefs(context).edit().putLong("apk_update_checked",System.currentTimeMillis()).apply();
                MAIN.post(()->{
                    Activity target=checkTarget!=null ? checkTarget.get() : null;
                    if(target==null || target.isFinishing() || target.isDestroyed()) return;
                    if(release.code>BuildConfig.VERSION_CODE) new AlertDialog.Builder(target)
                        .setTitle("SorryRKN "+release.name).setMessage(release.notes+"\n\nСкачать обновление ("+Math.round(release.size/1048576.0)+" МБ)?")
                        .setPositiveButton("Обновить",(d,w)->download(target,release)).setNegativeButton("Позже",null).show();
                    else if(checkForce) toast(target,"Установлена последняя версия SorryRKN");
                });
            } catch(Exception e) { MAIN.post(()->{
                Activity target=checkTarget!=null ? checkTarget.get() : null;
                if(checkForce && target!=null && !target.isFinishing() && !target.isDestroyed())
                    toast(target,"Не удалось проверить APK. Попробуйте позже.");
            }); }
            finally { MAIN.post(()->{checking=false;checkTarget=null;}); }
        });
    }
    private static InputStream open(String value) throws Exception {
        return open(value,false);
    }
    private static InputStream open(String value,boolean refresh) throws Exception {
        URL url=safeUrl(value);
        for(int i=0;i<6;i++) {
            HttpURLConnection c=(HttpURLConnection)url.openConnection();
            c.setConnectTimeout(8000); c.setReadTimeout(15000); c.setInstanceFollowRedirects(false);
            c.setRequestProperty("User-Agent","SorryRKN/"+BuildConfig.VERSION_NAME);
            if(refresh) {c.setUseCaches(false);c.setRequestProperty("Cache-Control","no-cache");}
            int code=c.getResponseCode();
            if(code==301 || code==302 || code==303 || code==307 || code==308) {
                String location=c.getHeaderField("Location"); c.disconnect();
                if(location==null) throw new IOException("Пустой редирект");
                url=safeUrl(new URL(url,location).toString()); continue;
            }
            if(code!=200) {c.disconnect();throw new IOException("HTTP "+code);}
            return new FilterInputStream(c.getInputStream()) { @Override public void close() throws IOException {try{super.close();}finally{c.disconnect();}} };
        }
        throw new IOException("Слишком много редиректов");
    }
    private static void download(Activity activity, Release release) {
        if(downloading) return; downloading=true;
        toast(activity,"Скачиваем обновление…"); Context context=activity.getApplicationContext();
        WORK.execute(()->{
            File temp=new File(context.getCacheDir(),"update.part"), apk=new File(context.getCacheDir(),"update.apk");
            try {
                MessageDigest digest=MessageDigest.getInstance("SHA-256"); long total=0, deadline=SystemClock.elapsedRealtime()+180000;
                try(InputStream in=open(release.url); OutputStream out=new FileOutputStream(temp)) {
                    byte[] b=new byte[65536]; int n;
                    while((n=in.read(b))!=-1) {
                        total+=n;
                        if(total>release.size || SystemClock.elapsedRealtime()>deadline) throw new IOException("Загрузка прервана");
                        out.write(b,0,n); digest.update(b,0,n);
                    }
                }
                if(total!=release.size || !hex(digest.digest()).equals(release.sha)) throw new IOException("Контрольная сумма не совпала");
                verifyArchive(context,temp,release.code);
                if(apk.exists() && !apk.delete()) throw new IOException("Не удалось заменить APK");
                if(!temp.renameTo(apk)) throw new IOException("Не удалось сохранить APK");
                Settings.prefs(context).edit().putInt("pending_apk_code",release.code).apply();
                MAIN.post(()->{
                    if(!activity.isFinishing() && !activity.isDestroyed()) {
                        if(!activity.getPackageManager().canRequestPackageInstalls()) new AlertDialog.Builder(activity)
                            .setTitle("Установка обновления").setMessage("Разрешите SorryRKN устанавливать обновления. Затем вернитесь в приложение.")
                            .setPositiveButton("Настройки",(d,w)->activity.startActivity(new Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,Uri.parse("package:"+activity.getPackageName()))))
                            .setNegativeButton("Позже",null).show();
                        else install(activity);
                    }
                });
            } catch(Exception e) {temp.delete(); MAIN.post(()->toast(activity,"Не удалось загрузить или проверить обновление. Попробуйте позже."));}
            finally {MAIN.post(()->downloading=false);}
        });
    }
    @SuppressWarnings("deprecation")
    static void verifyArchive(Context c,File apk,int expected) throws Exception {
        PackageManager pm=c.getPackageManager();
        int flags=Build.VERSION.SDK_INT>=28?PackageManager.GET_SIGNING_CERTIFICATES:PackageManager.GET_SIGNATURES;
        PackageInfo candidate=pm.getPackageArchiveInfo(apk.getPath(),flags), installed=pm.getPackageInfo(c.getPackageName(),flags);
        if(candidate==null || !candidate.packageName.equals(c.getPackageName()) || candidate.versionCode!=expected)
            throw new IOException("APK не соответствует релизу");
        Signature[] a=Build.VERSION.SDK_INT>=28?candidate.signingInfo.getApkContentsSigners():candidate.signatures;
        Signature[] b=Build.VERSION.SDK_INT>=28?installed.signingInfo.getApkContentsSigners():installed.signatures;
        if(a==null || b==null || a.length!=b.length || a.length==0) throw new IOException("Отсутствует подпись APK");
        Set<String> current=new HashSet<>(), next=new HashSet<>();
        for(Signature s:a) next.add(hex(MessageDigest.getInstance("SHA-256").digest(s.toByteArray())));
        for(Signature s:b) current.add(hex(MessageDigest.getInstance("SHA-256").digest(s.toByteArray())));
        if(!current.equals(next)) throw new IOException("Подпись APK изменилась");
    }
    static void resume(Activity a) {
        int code=Settings.prefs(a).getInt("pending_apk_code",0);
        if(code<=BuildConfig.VERSION_CODE) {Settings.prefs(a).edit().remove("pending_apk_code").apply();return;}
        if(!downloading && a.getPackageManager().canRequestPackageInstalls()) install(a);
    }
    private static void install(Activity a) {
        int expected=Settings.prefs(a).getInt("pending_apk_code",0);
        File apk=new File(a.getCacheDir(),"update.apk");
        try {
            verifyArchive(a,apk,expected);
            if(expected<=BuildConfig.VERSION_CODE) return;
            Uri uri=Uri.parse("content://"+a.getPackageName()+".updates/update.apk");
            a.startActivity(new Intent(Intent.ACTION_VIEW).setDataAndType(uri,"application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION));
            Settings.prefs(a).edit().remove("pending_apk_code").apply();
        } catch(Exception e) {toast(a,"Не удалось открыть установщик обновления");}
    }
    static String hex(byte[] data) {StringBuilder s=new StringBuilder();for(byte b:data)s.append(String.format(Locale.ROOT,"%02x",b&255));return s.toString();}
    private static void toast(Context c,String text) {Toast.makeText(c,text,Toast.LENGTH_LONG).show();}
}
