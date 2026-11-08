package dev.graybridge;

import android.app.*;
import android.content.*;
import android.net.VpnService;
import android.os.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.*;
import org.json.*;

/** Explicit emulator fixture, separate probe UID, real Naive and Xray executables. */
final class HTTPSRelayDeviceChecks {
    static void run(Instrumentation test,Context c,Bundle report) throws Exception {
        String mode=Settings.prefs(c).getString("remote_mode","server");
        JSONObject saved=RemoteVault.read(c,"server");
        Activity activity=null;
        try {
            File input=new File(c.getFilesDir(),"https-relay-probe.json");
            JSONObject fixture=new JSONObject(new String(Files.readAllBytes(input.toPath()),StandardCharsets.UTF_8));input.delete();
            if(NaiveEngine.relay(fixture.getString("https"))==null)throw new AssertionError("Missing full relay");
            if(VpnService.prepare(c)!=null)throw new AssertionError("Test emulator requires VPN consent");
            Settings.prefs(c).edit().putString("remote_mode","server").commit();
            RemoteVault.write(c,"server",fixture);
            activity=test.startActivitySync(new Intent(c,RemoteActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            RemoteVpnService.start(c);await(c,"on");
            CountDownLatch done=new CountDownLatch(1);String[] result={""};
            BroadcastReceiver receiver=new BroadcastReceiver(){public void onReceive(Context ignored,Intent intent){result[0]=intent.getStringExtra("result");done.countDown();}};
            IntentFilter filter=new IntentFilter("dev.graybridge.probe.RESULT");
            if(Build.VERSION.SDK_INT>=33)c.registerReceiver(receiver,filter,Context.RECEIVER_EXPORTED);else c.registerReceiver(receiver,filter);
            try {
                c.startActivity(new Intent().setComponent(new ComponentName("dev.graybridge.probe","dev.graybridge.probe.ProbeActivity"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TASK).putExtra("callbackPackage",c.getPackageName()).putExtra("requireVpn",true));
                if(!done.await(45,TimeUnit.SECONDS)||!result[0].startsWith("PASS"))throw new AssertionError("HTTPS cross-UID: "+result[0]);
                report.putString("https_tcp_udp",result[0]+" via Naive HTTPS CONNECT and encapsulated VLESS");
            }finally{c.unregisterReceiver(receiver);}
        }finally{
            if(RemoteVpnService.busy(c)){RemoteVpnService.stop(c);await(c,"off");}
            RemoteVault.write(c,"server",saved);Settings.prefs(c).edit().putString("remote_mode",mode).commit();
            if(activity!=null){Activity a=activity;test.runOnMainSync(a::finish);}
        }
    }
    private static void await(Context c,String wanted)throws Exception{
        long end=SystemClock.elapsedRealtime()+15000;
        while(SystemClock.elapsedRealtime()<end){String state=RemoteVpnService.status(c);if(wanted.equals(state))return;
            if(state.equals("error"))throw new AssertionError(Settings.prefs(c).getString("remote_error","error"));Thread.sleep(100);}
        throw new AssertionError("Timeout waiting for "+wanted);
    }
}
