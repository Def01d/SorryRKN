package dev.graybridge;

import android.app.*;
import android.content.*;
import android.net.VpnService;
import android.os.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.*;
import org.json.*;

/** Device-wide Xray route via an authenticated, loopback-only SOCKS listener. */
public class RemoteVpnService extends VpnService {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private java.lang.Process engine;
    private java.lang.Process httpsEngine;
    private Thread tunnel;
    private ParcelFileDescriptor fd;
    private File yaml;
    private boolean active;
    private NaiveEngine naive;
    static String status(Context c) { return Settings.prefs(c).getString("remote_state", "off"); }
    static boolean busy(Context c) { return java.util.Arrays.asList("starting", "on", "stopping").contains(status(c)); }
    static void state(Context c, String value, String error) {
        Settings.prefs(c).edit().putString("remote_state", value).putString("remote_error", error).apply();
    }
    static void start(Context c) {
        state(c, "starting", "");
        c.startForegroundService(new Intent(c, RemoteVpnService.class));
    }
    static void stop(Context c) {
        state(c, "stopping", "");
        c.startService(new Intent(c, RemoteVpnService.class).setAction("stop"));
    }
    @Override public int onStartCommand(Intent intent, int flags, int id) {
        if (intent == null || "stop".equals(intent.getAction())) {
            worker.execute(() -> finish(id, ""));
            return START_NOT_STICKY;
        }
        NotificationManager nm=getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("remote", "VPN", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 5, new Intent(this, RemoteActivity.class),
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        startForeground(213, new Notification.Builder(this,"remote").setSmallIcon(R.drawable.ic_bridge)
            .setContentTitle("SorryRKN · VPN").setContentText("Защищённое подключение").setContentIntent(open).setOngoing(true).build());
        worker.execute(() -> {
            if (active) return;
            try {
                startEngine();
                active = true;
                state(this, "on", "");
                java.lang.Process child = engine;
                new Thread(() -> {
                    try { child.waitFor(); worker.execute(() -> {
                        if (engine == child) finish(id, "Соединение завершилось.");
                    }); } catch (InterruptedException | RejectedExecutionException ignored) { }
                }, "xray-exit").start();
                java.lang.Process httpsChild=httpsEngine;
                if(httpsChild!=null)new Thread(()->{
                    try {httpsChild.waitFor();worker.execute(()->{if(httpsEngine==httpsChild)finish(id,"HTTPS-соединение завершилось.");});}
                    catch(InterruptedException | RejectedExecutionException ignored){}
                },"https-exit").start();
            } catch (Exception | LinkageError e) {
                finish(id, "Не удалось открыть туннель. Проверьте разрешение VPN и параметры узла.");
            }
        });
        return START_NOT_STICKY;
    }
    private void startEngine() throws Exception {
        boolean self=Settings.prefs(this).getString("remote_mode","server").equals("server");
        int port;
        try (ServerSocket reserve = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) { port = reserve.getLocalPort(); }
        String password = UUID.randomUUID().toString();
        boolean fullRelay=false;
        if(self) {
            String profile=RemoteVault.read(this,"server").getString("https");
            naive=new NaiveEngine();
            engine=naive.start(this,profile,port,password);
            awaitSocks(port,password);
            naive.ready();
            String relay=NaiveEngine.relay(profile);
            if(relay!=null) {
                fullRelay=true;
                httpsEngine=engine;
                int httpsPort=port;
                try(ServerSocket reserve=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){port=reserve.getLocalPort();}
                JSONObject user=new JSONObject().put("id",relay).put("encryption","none");
                JSONObject peer=new JSONObject().put("address","relay.sorryrkn.invalid").put("port",443)
                    .put("users",new JSONArray().put(user));
                JSONObject outbound=new JSONObject().put("tag","remote").put("protocol","vless")
                    .put("settings",new JSONObject().put("vnext",new JSONArray().put(peer)))
                    .put("streamSettings",new JSONObject().put("network","tcp").put("security","none")
                        .put("sockopt",new JSONObject().put("dialerProxy","https")));
                JSONObject local=new JSONObject().put("address","127.0.0.1").put("port",httpsPort)
                    .put("users",new JSONArray().put(new JSONObject().put("user","local").put("pass",password)));
                JSONObject https=new JSONObject().put("tag","https").put("protocol","socks")
                    .put("settings",new JSONObject().put("servers",new JSONArray().put(local)));
                startXray(port,password,new JSONArray().put(outbound).put(https));
            }
        } else {
            startXray(port,password,RemoteSubscriptions.outbound(this));
        }
        awaitSocks(port, password);
        if(naive!=null)naive.ready();
        startTun(port,password,self && !fullRelay);
    }
    private void startXray(int port,String password, JSONObject outbound) throws Exception {
        startXray(port,password,new JSONArray().put(outbound));
    }
    private void startXray(int port,String password, JSONArray outbounds) throws Exception {
        JSONObject account = new JSONObject().put("user", "local").put("pass", password);
        JSONObject settings = new JSONObject().put("auth", "password").put("accounts", new JSONArray().put(account)).put("udp", true).put("ip","127.0.0.1");
        JSONObject listener = new JSONObject().put("port",port).put("listen","127.0.0.1").put("protocol","socks").put("settings",settings);
        JSONObject config = new JSONObject().put("inbounds",new JSONArray().put(listener)).put("outbounds",outbounds)
            .put("log", new JSONObject().put("loglevel","none"));
        File exe = new File(getApplicationInfo().nativeLibraryDir,"libxray.so");
        engine = new ProcessBuilder(exe.toString(),"run","-config","stdin:").redirectError(new File("/dev/null")).redirectOutput(new File("/dev/null")).start();
        try (OutputStream in = engine.getOutputStream()) { in.write(config.toString().getBytes(StandardCharsets.UTF_8)); }
    }
    private void startTun(int port,String password,boolean self) throws Exception {
        yaml = File.createTempFile("remote-", ".yml", getCacheDir());
        String text="tunnel:\n  mtu: 1400\n  ipv4: 198.18.0.1\n  ipv6: 'fd00:1::1'\n" +
            "socks5:\n  address: 127.0.0.1\n  port: "+port+"\n  username: local\n  password: '"+password+"'\n  udp: 'udp'\n"+
            (self?"mapdns:\n  address: 198.18.0.2\n  port: 53\n  network: 100.64.0.0\n  netmask: 255.192.0.0\n  cache-size: 4096\n":"")+
            "misc:\n  task-stack-size: 86016\n  max-session-count: 512\n  log-level: error\n";
        try (OutputStream out = new FileOutputStream(yaml)) { out.write(text.getBytes(StandardCharsets.UTF_8)); }
        Builder builder = new Builder().setSession(self?"SorryRKN · HTTPS":"SorryRKN · Xray").setMtu(1400)
            .addAddress("198.18.0.1",32).addAddress("fd00:1::1",128).addRoute("0.0.0.0",0).addRoute("::",0)
            .addDnsServer(self?"198.18.0.2":"1.1.1.1").addDisallowedApplication(getPackageName()).setBlocking(false);
        fd = builder.establish();
        if(fd == null) throw new IOException();
        final int descriptor = fd.getFd();
        final java.lang.Process child = engine;
        tunnel = new Thread(() -> {
            NativeTunnel.run(yaml.getPath(),descriptor);
            try { worker.execute(() -> { if (engine == child) finish(0, "Интерфейс VPN закрыт."); }); }
            catch (RejectedExecutionException ignored) { }
        }, "remote-tun");
        tunnel.start();
    }
    private void awaitSocks(int port, String password) throws Exception {
        byte[] auth = password.getBytes(StandardCharsets.US_ASCII);
        for (int i=0; i<60 && engine.isAlive(); i++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 200);
                socket.setSoTimeout(1000);
                OutputStream out = socket.getOutputStream(); InputStream in = socket.getInputStream();
                out.write(new byte[]{5,1,2});
                if (in.read()!=5 || in.read()!=2) throw new IOException();
                out.write(new byte[]{1,5,'l','o','c','a','l',(byte)auth.length}); out.write(auth);
                if (in.read()!=1 || in.read()!=0) throw new IOException();
                return;
            } catch (IOException e) { Thread.sleep(100); }
        }
        throw new IOException("Xray listener failed");
    }
    @Override public void onRevoke() { worker.execute(() -> finish(0, "")); }
    @Override public void onDestroy() { worker.execute(this::close); worker.shutdown(); super.onDestroy(); }
    private void finish(int id,String error) {
        close();
        state(this,error.isEmpty()?"off":"error",error);
        stopForeground(STOP_FOREGROUND_REMOVE);
        if(id==0) stopSelf(); else stopSelfResult(id);
    }
    private void close() {
        active = false;
        if (engine!=null) { engine.destroyForcibly(); engine=null; }
        if (httpsEngine!=null) { httpsEngine.destroyForcibly(); httpsEngine=null; }
        if (tunnel!=null) {
            while(tunnel.isAlive()) {
                NativeTunnel.quit();
                try { tunnel.join(100); } catch (InterruptedException e) {Thread.currentThread().interrupt();break;}
            }
            tunnel=null;
        }
        if(fd!=null) { try { fd.close(); } catch(IOException ignored) { } fd=null; }
        if(yaml!=null) { yaml.delete(); yaml=null; }
        if(naive!=null){naive.close();naive=null;}
    }
}
