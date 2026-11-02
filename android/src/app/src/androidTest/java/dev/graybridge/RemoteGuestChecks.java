package dev.graybridge;

import android.app.*;
import android.content.*;
import android.os.*;
import org.json.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/** Test-only credentials and trusted host fingerprints come from the isolated fixture. */
final class RemoteGuestChecks {
    static void run(Instrumentation test,Context c,Bundle report) throws Exception {
        File credentials=new File(c.getFilesDir(),"guest-probe.json");
        JSONObject target=new JSONObject(new String(Files.readAllBytes(credentials.toPath()),StandardCharsets.UTF_8));
        credentials.delete();
        JSONObject saved=RemoteVault.read(c,"server");
        Activity activity=null;
        try {
            activity=test.startActivitySync(new Intent(c,RemoteActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            JSONObject server=new JSONObject().put("host",target.getString("host")).put("port",target.getInt("port")).put("user",target.getString("user"));
            String password=target.getString("password");
            try { ServerSSH.run(c,server,password,"https-status");throw new AssertionError("Unknown host accepted"); }
            catch(ServerSSH.Untrusted observed) {
                if(!target.getString("trusted").contains(observed.fingerprint))throw new AssertionError("Unexpected SSH key");
                server.put("pin",observed.fingerprint);
            }
            String vpn=ServerSSH.run(c,server,password,"https-on");ServerSSH.apply(server,vpn);
            String socks=ServerSSH.run(c,server,password,"install-socks");ServerSSH.apply(server,socks);
            String status=ServerSSH.apply(server,ServerSSH.run(c,server,password,"https-status"));
            if(!status.contains("vpn:running") || !status.contains("socks:running"))throw new AssertionError("Guest service status");
            report.putString("ssh","Pinned Ubuntu SSH, HTTPS/SOCKS provisioning and status passed");
            if(target.has("httpsPort")) server.put("https",server.getString("https").replace(":443/?",":"+target.getInt("httpsPort")+"/?"));
            // The activity requests VPN preparation before establishing the interface, even with pre-granted consent.
            if(android.net.VpnService.prepare(c)!=null)throw new AssertionError("Test emulator requires VPN consent");
            RemoteVault.write(c,"server",server);RemoteVpnService.start(c);
            long deadline=SystemClock.elapsedRealtime()+15000;
            while(!RemoteVpnService.status(c).equals("on") && SystemClock.elapsedRealtime()<deadline) Thread.sleep(100);
            if(!RemoteVpnService.status(c).equals("on"))throw new AssertionError("HTTPS interface did not start");
            String[] fields=socks.split("\\t");
            try(Socket socket=new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1",SshForward.port()),12000);socket.setSoTimeout(8000);
                OutputStream out=socket.getOutputStream();InputStream in=socket.getInputStream();
                out.write(new byte[]{5,1,2});if(in.read()!=5||in.read()!=2)throw new AssertionError("SOCKS auth method");
                byte[] user=fields[4].getBytes(StandardCharsets.US_ASCII),pass=fields[5].getBytes(StandardCharsets.US_ASCII);
                out.write(1);out.write(user.length);out.write(user);out.write(pass.length);out.write(pass);
                if(in.read()!=1||in.read()!=0)throw new AssertionError("SOCKS credentials refused");
            }
            report.putString("private_socks","Authenticated at private SOCKS endpoint via pinned SSH forward");
            String token=java.util.UUID.randomUUID().toString();
            java.util.concurrent.CountDownLatch done=new java.util.concurrent.CountDownLatch(1);String[] result={""};
            BroadcastReceiver receiver=new BroadcastReceiver(){public void onReceive(Context ctx,Intent msg){
                if(token.equals(msg.getStringExtra("probeToken"))){result[0]=msg.getStringExtra("result");done.countDown();}
            }};
            IntentFilter filter=new IntentFilter("dev.graybridge.probe.RESULT");
            if(Build.VERSION.SDK_INT>=33)c.registerReceiver(receiver,filter,Context.RECEIVER_EXPORTED);else c.registerReceiver(receiver,filter);
            try {
                c.startActivity(new Intent().setComponent(new ComponentName("dev.graybridge.probe","dev.graybridge.probe.ProbeActivity"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TASK).putExtra("callbackPackage",c.getPackageName())
                    .putExtra("remoteHttps",true).putExtra("probeToken",token));
                if(!done.await(40,java.util.concurrent.TimeUnit.SECONDS)||!result[0].equals("PASS"))throw new AssertionError("HTTPS probe: "+result[0]);
                report.putString("https_connect","Separate UID reached public HTTPS via Android TUN and authenticated Chromium CONNECT to guest");
            } finally{c.unregisterReceiver(receiver);}
            NegativeTrustProbe.run(c,server.getString("https"));
            report.putString("negative_tls","Alternate CA for the same private HTTPS server prevented upstream communication");
        } finally {
            if(RemoteVpnService.busy(c)) {
                RemoteVpnService.stop(c);long end=SystemClock.elapsedRealtime()+8000;
                while(RemoteVpnService.busy(c)&&SystemClock.elapsedRealtime()<end) Thread.sleep(100);
            }
            SshForward.stop(c);RemoteVault.write(c,"server",saved);
            if(activity!=null){Activity a=activity;test.runOnMainSync(a::finish);}
        }
    }
}
