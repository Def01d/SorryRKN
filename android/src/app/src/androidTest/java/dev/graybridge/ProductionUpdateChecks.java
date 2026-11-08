package dev.graybridge;

import android.app.*;
import android.content.*;
import android.os.*;
import android.view.accessibility.AccessibilityNodeInfo;
import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

/** Explicit checks on the isolated emulator's real release package and signer. */
final class ProductionUpdateChecks {
    static void run(Instrumentation test,Context c,Bundle args,Bundle report)throws Exception {
        if(!c.getPackageName().equals("io.github.def01d.sorryrkn"))throw new AssertionError("Requires the production package");
        String mode=args.getString("productionUpdateChecks");
        if("seed".equals(mode)) {
            String marker=UUID.randomUUID().toString();
            Settings.prefs(c).edit().putString("lineage_marker",marker).putInt("lineage_uid",c.getApplicationInfo().uid)
                .putString("lineage_secret_sha",hash(Settings.secret(c))).putBoolean("auto_updates",false).commit();
            RemoteVault.write(c,"upgrade-check",new JSONObject().put("marker",marker));
            report.putString("seed","Production baseline state and AndroidKeyStore-encrypted vault saved");return;
        }
        if("candidate".equals(mode)) {
            File candidate=copy(test,c,args.getString("candidate"),"update.part");
            AppUpdates.verifyArchive(c,candidate,10000);candidate.delete();
            android.content.pm.ProviderInfo provider=c.getPackageManager().resolveContentProvider(c.getPackageName()+".updates",0);
            if(provider==null || provider.exported || !provider.grantUriPermissions || provider.applicationInfo.uid!=c.getApplicationInfo().uid)
                throw new AssertionError("Invalid production APK update provider");
            File wrong=copy(test,c,args.getString("wrongSigner"),"wrong-signer.apk");
            try{AppUpdates.verifyArchive(c,wrong,10000);throw new AssertionError("Different APK signer accepted");}
            catch(IOException expected){}finally{wrong.delete();}
            report.putString("archive","Production signer accepted; same-package APK with a different signer rejected");return;
        }
        if("verify".equals(mode)) {
            String marker=Settings.prefs(c).getString("lineage_marker","");
            if(marker.isEmpty() || !marker.equals(RemoteVault.read(c,"upgrade-check").getString("marker")) ||
                !Settings.prefs(c).getString("lineage_secret_sha","").equals(hash(Settings.secret(c))) ||
                Settings.prefs(c).getInt("lineage_uid",-1)!=c.getApplicationInfo().uid || c.getPackageManager().getPackageInfo(c.getPackageName(),0).versionCode!=10000)
                throw new AssertionError("State, signing identity or UID did not survive upgrade");
            report.putString("upgrade","In-place production APK upgrade preserved UID, Telegram secret, preferences and AndroidKeyStore vault");return;
        }
        if("offer".equals(mode) || "download".equals(mode)) {
            if(c.getPackageManager().getPackageInfo(c.getPackageName(),0).versionCode>=10000)throw new AssertionError("Install the signed baseline first");
            Settings.prefs(c).edit().remove("apk_update_url").putBoolean("auto_updates",false)
                .putLong("apk_update_checked",System.currentTimeMillis()).commit();
            Activity activity=null;
            try {
                activity=test.startActivitySync(new Intent(c,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
                if("download".equals(mode)) {
                    File apk=new File(c.getCacheDir(),"update.apk");apk.delete();
                    offer(test);click(test,"Обновить");
                    long end=System.currentTimeMillis()+210000;
                    while(!apk.exists() && System.currentTimeMillis()<end)Thread.sleep(200);
                    if(!apk.exists())throw new AssertionError("Production APK download did not finish");
                    String wanted=args.getString("expectedSha");
                    if(wanted==null || !wanted.matches("[0-9a-f]{64}"))throw new AssertionError("Missing expected APK hash");
                    MessageDigest digest=MessageDigest.getInstance("SHA-256");
                    try(InputStream in=new FileInputStream(apk)){byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1)digest.update(b,0,n);}
                    if(!wanted.equals(AppUpdates.hex(digest.digest())))throw new AssertionError("Downloaded APK differs from tagged release");
                    AppUpdates.verifyArchive(c,apk,10000);
                    report.putString("download","Real startup update downloaded the immutable tagged APK and verified hash, package, version and production signer");return;
                }
                offer(test);dismiss(test);
                long checked=Settings.prefs(c).getLong("apk_update_checked",0);
                shell(test,"input keyevent 3");Thread.sleep(200);
                shell(test,"am start -W -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -f 0x10000000 -n "+c.getPackageName()+"/dev.graybridge.MainActivity");
                offer(test);dismiss(test);
                if(Settings.prefs(c).getLong("apk_update_checked",0)<=checked)throw new AssertionError("Reopen did not check again");
                report.putString("startup_offer","Real signed android-update.json offered production 1.0.0 on launch and HOME/reopen despite a recent check");
            }finally{if(activity!=null){Activity a=activity;test.runOnMainSync(a::finish);}}
            return;
        }
        throw new AssertionError("Unknown production update check");
    }
    private static String hash(String text)throws Exception{return AppUpdates.hex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));}
    private static File copy(Instrumentation test,Context c,String source,String name)throws Exception {
        if(source==null || !source.matches("/data/local/tmp/[A-Za-z0-9._-]+\\.apk"))throw new AssertionError("Unexpected fixture path");
        File target=new File(c.getCacheDir(),name);
        try(ParcelFileDescriptor fd=test.getUiAutomation().executeShellCommand("cat "+source);
            InputStream in=new FileInputStream(fd.getFileDescriptor());OutputStream out=new FileOutputStream(target)) {
            byte[] b=new byte[65536];int n;long total=0;
            while((n=in.read(b))!=-1){total+=n;if(total>AppUpdates.MAX_APK)throw new IOException("Fixture too large");out.write(b,0,n);}
        }
        return target;
    }
    private static void shell(Instrumentation test,String command)throws Exception {
        try(ParcelFileDescriptor fd=test.getUiAutomation().executeShellCommand(command);InputStream in=new FileInputStream(fd.getFileDescriptor())){while(in.read()!=-1){}}
    }
    private static AccessibilityNodeInfo node(Instrumentation test,String text){
        AccessibilityNodeInfo root=test.getUiAutomation().getRootInActiveWindow();if(root==null)return null;
        java.util.List<AccessibilityNodeInfo> list=root.findAccessibilityNodeInfosByText(text);return list.isEmpty()?null:list.get(0);
    }
    private static void offer(Instrumentation test)throws Exception {
        long end=System.currentTimeMillis()+25000;
        while(System.currentTimeMillis()<end){if(node(test,"SorryRKN 1.0.0")!=null)return;Thread.sleep(100);}
        throw new AssertionError("Missing production update offer");
    }
    private static void dismiss(Instrumentation test)throws Exception {
        click(test,"Позже");
        test.waitForIdleSync();Thread.sleep(200);
    }
    private static void click(Instrumentation test,String title)throws Exception {
        AccessibilityNodeInfo button=node(test,title);if(button==null||!button.performAction(AccessibilityNodeInfo.ACTION_CLICK))throw new AssertionError("Missing button "+title);
    }
}
