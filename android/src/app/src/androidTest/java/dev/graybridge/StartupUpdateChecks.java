package dev.graybridge;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.accessibility.AccessibilityNodeInfo;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.HttpsURLConnection;

/** Intercepts HTTPS in the test process only; no update/download hooks in the app. */
final class StartupUpdateChecks {
    static void run(Instrumentation test,Context context,Bundle report) throws Exception {
        AtomicInteger requests=new AtomicInteger();
        CountDownLatch pending=new CountDownLatch(1),release=new CountDownLatch(1);
        byte[] manifest=new org.json.JSONObject().put("versionCode",BuildConfig.VERSION_CODE+1)
            .put("versionName","next-test").put("url","https://update-check.test/app.apk")
            .put("size",20000000).put("sha256",new String(new char[64]).replace('\0','a'))
            .put("notes","Test-only update offer").toString().getBytes("UTF-8");
        URL.setURLStreamHandlerFactory(protocol->!protocol.equals("https")?null:new URLStreamHandler(){
            @Override protected URLConnection openConnection(URL url) throws IOException {
                if(!url.toString().equals("https://update-check.test/update.json"))throw new IOException("Unexpected test HTTPS request");
                return new HttpsURLConnection(url) {
                    @Override public int getResponseCode() throws IOException {
                        if(getUseCaches()||!"no-cache".equals(getRequestProperty("Cache-Control")))throw new IOException("Manifest cache enabled");
                        if(requests.incrementAndGet()==3) {
                            pending.countDown();
                            try {if(!release.await(10,TimeUnit.SECONDS))throw new IOException("Test response not released");}
                            catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException(e);}
                        }
                        return 200;
                    }
                    @Override public InputStream getInputStream(){return new ByteArrayInputStream(manifest);}
                    @Override public String getCipherSuite(){return "test-only";}
                    @Override public java.security.cert.Certificate[] getLocalCertificates(){return null;}
                    @Override public java.security.cert.Certificate[] getServerCertificates(){return new java.security.cert.Certificate[0];}
                    @Override public void connect(){}
                    @Override public void disconnect(){}
                    @Override public boolean usingProxy(){return false;}
                };
            }
        });
        SharedPreferences prefs=Settings.prefs(context);
        String oldSource=prefs.getString("apk_update_url",AppUpdates.SOURCE);
        boolean oldUpdates=prefs.getBoolean("auto_updates",true);
        long oldChecked=prefs.getLong("apk_update_checked",0);
        Activity first=null,second=null;
        try {
            prefs.edit().putString("apk_update_url","https://update-check.test/update.json")
                .putBoolean("auto_updates",false).putLong("apk_update_checked",System.currentTimeMillis()).commit();
            first=test.startActivitySync(new Intent(context,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            offer(test,requests,1);
            dismiss(test);
            // Reuse the launcher task after HOME, well inside the former six-hour interval.
            try(android.os.ParcelFileDescriptor descriptor=test.getUiAutomation().executeShellCommand("input keyevent 3")) {
                try(InputStream input=new FileInputStream(descriptor.getFileDescriptor())){while(input.read()!=-1){}}
            }
            context.startActivity(new Intent(context,MainActivity.class).setAction(Intent.ACTION_MAIN)
                .addCategory(Intent.CATEGORY_LAUNCHER).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            offer(test,requests,2);dismiss(test);
            Activity original=first;test.runOnMainSync(original::finish);test.waitForIdleSync();
            first=test.startActivitySync(new Intent(context,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            if(!pending.await(5,TimeUnit.SECONDS))throw new AssertionError("Third check did not start");
            Activity replaced=first;test.runOnMainSync(replaced::finish);test.waitForIdleSync();
            second=test.startActivitySync(new Intent(context,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            test.waitForIdleSync();release.countDown();
            offer(test,requests,3);dismiss(test);
            if(requests.get()!=3)throw new AssertionError("Concurrent opening duplicated HTTP request");
            report.putString("startup_updates","PASS: recent check does not suppress launch; HOME/reopen checks again; in-flight check delivers to replacement Activity without duplicate HTTP; manifest bypasses cache; update dialog shown");
        } finally {
            release.countDown();
            if(first!=null){Activity activity=first;test.runOnMainSync(activity::finish);}
            if(second!=null){Activity activity=second;test.runOnMainSync(activity::finish);}
            prefs.edit().putString("apk_update_url",oldSource).putBoolean("auto_updates",oldUpdates)
                .putLong("apk_update_checked",oldChecked).commit();
        }
    }
    private static AccessibilityNodeInfo node(Instrumentation test,String text){
        AccessibilityNodeInfo root=test.getUiAutomation().getRootInActiveWindow();
        if(root==null)return null;
        java.util.List<AccessibilityNodeInfo> nodes=root.findAccessibilityNodeInfosByText(text);
        return nodes.isEmpty()?null:nodes.get(0);
    }
    private static void offer(Instrumentation test,AtomicInteger requests,int count)throws Exception {
        long deadline=System.currentTimeMillis()+8000;
        while(System.currentTimeMillis()<deadline){
            if(requests.get()==count&&node(test,"SorryRKN next-test")!=null)return;
            Thread.sleep(100);
        }
        throw new AssertionError("Missing update offer "+count+"; requests="+requests.get());
    }
    private static void dismiss(Instrumentation test)throws Exception {
        AccessibilityNodeInfo button=node(test,"Позже");
        if(button==null||!button.performAction(AccessibilityNodeInfo.ACTION_CLICK))throw new AssertionError("Cannot dismiss offer");
        test.waitForIdleSync();Thread.sleep(100);
    }
}
