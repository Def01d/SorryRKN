package dev.graybridge;

import android.app.*;
import android.content.*;
import android.os.*;
import java.io.*;
import java.net.*;
import java.util.UUID;
import java.util.concurrent.*;
import org.json.*;

/** Run on isolated emulator with VPN consent, separate probe APK and host echo fixtures. */
final class RemoteDeviceChecks {
    static void run(Instrumentation test,Context c,Bundle report) throws Exception {
        String priorMode=Settings.prefs(c).getString("remote_mode","server");
        Settings.prefs(c).edit().putString("remote_mode","subscriptions").commit();
        JSONObject savedLibrary=RemoteSubscriptions.library(c);
        Activity activity=null;
        java.lang.Process peer=null;
        try {
            if(android.net.VpnService.prepare(c)!=null) throw new AssertionError("Test VPN consent required");
            activity=test.startActivitySync(new Intent(c,RemoteActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            String id=UUID.randomUUID().toString();
            int port;try(ServerSocket free=new ServerSocket(0,1,InetAddress.getLoopbackAddress())){port=free.getLocalPort();}
            JSONObject inbound=new JSONObject().put("listen","127.0.0.1").put("port",port).put("protocol","vless")
                .put("settings",new JSONObject().put("decryption","none").put("clients",new JSONArray().put(new JSONObject().put("id",id))));
            // The test peer permits only the emulator host's two echo fixture ports.
            JSONObject permit=new JSONObject().put("action","allow").put("ip",new JSONArray().put("10.0.2.2/32")).put("port","18888-18889");
            JSONObject freedom=new JSONObject().put("protocol","freedom").put("settings",new JSONObject().put("finalRules",new JSONArray().put(permit)));
            JSONObject config=new JSONObject().put("inbounds",new JSONArray().put(inbound)).put("outbounds",new JSONArray().put(freedom));
            File fixtureLog=new File(c.getCacheDir(),"peer-test.log");
            peer=new ProcessBuilder(new File(c.getApplicationInfo().nativeLibraryDir,"libxray.so").toString(),"run","-config","stdin:")
                .redirectErrorStream(true).redirectOutput(fixtureLog).start();
            try(OutputStream in=peer.getOutputStream()){in.write(config.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));}
            RemoteSubscriptions.update(c,"vless://"+id+"@127.0.0.1:"+port+"?type=tcp&security=none#Test",false);
            String raw=Settings.prefs(c).getString("remote.subscriptions","");
            if(raw.contains(id) || raw.contains("vless://"))throw new AssertionError("Plaintext credential");
            RemoteVpnService.start(c);await(c,"on");
            CountDownLatch done=new CountDownLatch(1);
            String[] result={""};
            BroadcastReceiver receiver=new BroadcastReceiver(){public void onReceive(Context ignored,Intent intent){
                result[0]=intent.getStringExtra("result");done.countDown();
            }};
            IntentFilter filter=new IntentFilter("dev.graybridge.probe.RESULT");
            if(Build.VERSION.SDK_INT>=33)c.registerReceiver(receiver,filter,Context.RECEIVER_EXPORTED);else c.registerReceiver(receiver,filter);
            try {
                c.startActivity(new Intent().setComponent(new ComponentName("dev.graybridge.probe","dev.graybridge.probe.ProbeActivity"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TASK).putExtra("callbackPackage",c.getPackageName()).putExtra("requireVpn",true));
                if(!done.await(45,TimeUnit.SECONDS)||!result[0].startsWith("PASS"))throw new AssertionError("Cross-UID tunnel: "+result[0]);
            } finally {c.unregisterReceiver(receiver);}
            report.putString("xray",result[0]);
            RemoteVpnService.stop(c);await(c,"off");
        } finally {
            if(peer!=null)peer.destroyForcibly();
            if(RemoteVpnService.busy(c)){RemoteVpnService.stop(c);await(c,"off");}
            RemoteVault.write(c,"subscriptions",savedLibrary);Settings.prefs(c).edit().putString("remote_mode",priorMode).commit();
            if(activity!=null){Activity a=activity;test.runOnMainSync(a::finish);}
        }
    }
    private static void await(Context c,String target) throws Exception {
        long deadline=SystemClock.elapsedRealtime()+15000;
        while(SystemClock.elapsedRealtime()<deadline){String s=RemoteVpnService.status(c);if(target.equals(s))return;
            if(s.equals("error"))throw new AssertionError(Settings.prefs(c).getString("remote_error","error"));Thread.sleep(100);}
        throw new AssertionError("Timeout waiting for "+target);
    }
}
