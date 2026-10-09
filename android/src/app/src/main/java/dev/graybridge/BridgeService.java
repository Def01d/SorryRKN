package dev.graybridge;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.net.*;
import android.os.*;
import android.service.quicksettings.TileService;
import com.chaquo.python.Python;
import com.chaquo.python.PyObject;
import com.chaquo.python.android.AndroidPlatform;
import java.io.*;
import java.lang.Process;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.json.JSONObject;
import org.json.JSONArray;

public class BridgeService extends VpnService {
    public static final String START = "dev.graybridge.START", STOP = "dev.graybridge.STOP", RETEST = "dev.graybridge.RETEST";
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private volatile boolean desired;
    private volatile boolean destroyed;
    private ParcelFileDescriptor tun;
    private Process tpws;
    private Process discordProcess;
    private Process instagramProcess;
    private Strategies.Profile youtubeProfile,discordProfile;
    private Thread tunnelThread;
    private PyObject engine;
    private volatile boolean started;
    private int commandId;
    private ConnectivityManager connectivity;
    private String networkHandle = "";
    private boolean watchingNetwork;
    private boolean dpiActive;
    private boolean vpnActive;
    private boolean extended;
    private boolean forceSelection;
    private StrategyMemory.Choice cachedChoice;
    private String choiceNetworkKey;
    private long connectedAt;
    private int recoveryFailures;
    private boolean recovering;
    private final Runnable reconnect = () -> worker.execute(() -> {
        if(desired && !started && !destroyed)openResources();
    });
    private final Runnable networkChanged = () -> {
        if (desired && started && !networkIdentity().equals(networkHandle))
            worker.execute(() -> {
                Settings.prefs(this).edit().putInt("network_reconnect_count",Settings.prefs(this).getInt("network_reconnect_count",0)+1).apply();
                extended=false; retest();
            });
    };
    private final ConnectivityManager.NetworkCallback networks = new ConnectivityManager.NetworkCallback() {
        private void changed() { main.removeCallbacks(networkChanged); main.postDelayed(networkChanged, 2500); }
        @Override public void onAvailable(Network n) { changed(); }
        @Override public void onLost(Network n) { changed(); }
        @Override public void onCapabilitiesChanged(Network n, NetworkCapabilities c) { changed(); }
        @Override public void onLinkPropertiesChanged(Network n, LinkProperties links) { changed(); }
    };

    public boolean keepRunning() { return desired && !destroyed; }

    @Override public void onCreate() {
        super.onCreate();
        connectivity = getSystemService(ConnectivityManager.class);
    }

    public static void retest(Context context) {
        retest(context,false);
    }
    public static void retest(Context context,boolean extended) {
        context.startService(new Intent(context, BridgeService.class).setAction(RETEST).putExtra("extended",extended));
    }
    private final Runnable health = new Runnable() {
        @Override public void run() {
            if (!desired || !started || destroyed) return;
            worker.execute(() -> {
                if (!desired || !started) return;
                try {
                    if(SystemClock.elapsedRealtime()-connectedAt>60000)recoveryFailures=0;
                    if ((vpnActive && (tunnelThread == null || !tunnelThread.isAlive())) ||
                        (dpiActive && (tpws==null || !tpws.isAlive() || (discordProcess!=null && !discordProcess.isAlive()))) ||
                        (instagramProcess!=null && !instagramProcess.isAlive()))
                        throw new IOException("Сетевой модуль остановился");
                    if (engine != null && !engine.callAttr("is_running").toBoolean())
                        throw new IOException("Локальный прокси остановился");
                    if(engine!=null) Settings.prefs(BridgeService.this).edit()
                        .putString("traffic_report",engine.callAttr("diagnostics").toString()).apply();
                    main.postDelayed(this, 3000);
                } catch (Exception e) { recover(e); }
            });
        }
    };

    public static void start(Context context) {
        context.startForegroundService(new Intent(context, BridgeService.class).setAction(START));
    }
    public static void stop(Context context) {
        context.startService(new Intent(context, BridgeService.class).setAction(STOP));
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        commandId = startId;
        if (intent != null && RETEST.equals(intent.getAction())) {
            extended=intent.getBooleanExtra("extended",false);
            forceSelection=true;
            if (desired && started) worker.execute(this::retest);
            else if (!desired) stopSelfResult(startId);
            return START_STICKY;
        }
        boolean stop = intent != null && STOP.equals(intent.getAction());
        desired = !stop && (intent != null || Settings.prefs(this).getBoolean("desired", false));
        Settings.prefs(this).edit().putBoolean("desired", desired).apply();
        if (!desired) {
            publish("stopping", "");
            worker.execute(() -> {
                closeResources();
                if (!desired) finishStopped("off", "", startId);
            });
            return START_NOT_STICKY;
        }
        foreground("Запуск подключения…");
        if (!started) {
            Settings.prefs(this).edit().putString("probe_status", "Запускаем локальное соединение")
                .putString("probe_result", "").putString("probe_report","[]")
                .putString("traffic_report","{}").remove("native_exit").apply();
            publish("starting", "");
        }
        DataUpdates.request(this, false);
        worker.execute(() -> {
            if (desired && !started && !destroyed) openResources();
        });
        return START_STICKY;
    }

    private void openResources() {
        try {
            if (!Settings.vpn(this) && !Settings.telegram(this))
                throw new IOException("Выберите сервис для подключения");
            if (Settings.vpn(this) && VpnService.prepare(this) != null)
                throw new IOException("Нужно разрешить локальное VPN-подключение");
            DataUpdates.module(this);
            dpiActive = false;
            vpnActive = false;
            youtubeProfile=null;discordProfile=null;cachedChoice=null;
            Network physical=underlying();
            networkHandle=networkIdentity();
            setUnderlyingNetworks(physical==null?null:new Network[]{physical});
            LinkProperties links=physical==null?null:connectivity.getLinkProperties(physical);
            JSONObject networkReport=new JSONObject().put("type",networkType());
            if(links!=null) {
                boolean ipv4=false,ipv6=false;
                for(LinkAddress address:links.getLinkAddresses()) {
                    if(address.getAddress() instanceof Inet4Address)ipv4=true;
                    if(address.getAddress() instanceof Inet6Address && !address.getAddress().isLinkLocalAddress())ipv6=true;
                }
                networkReport.put("ipv4",ipv4).put("ipv6",ipv6);
                if(Build.VERSION.SDK_INT>=29)networkReport.put("mtu",links.getMtu());
            }
            Settings.prefs(this).edit().putString("network_report",networkReport.toString()).apply();
            if (Settings.dpi(this)) {
                Strategies.Profile chosen = chooseStrategy();
                if (!desired) { closeResources(); return; }
                if(chosen!=null) {
                    tpws = launch(chosen, 1080, true);
                    awaitPort(1080); dpiActive = true;
                    if(discordProfile!=null && !discordProfile.id.equals(chosen.id)) {
                        discordProcess=launch(discordProfile,1083,true);
                        awaitPort(1083,discordProcess);
                    }
                } else if(!Settings.telegram(this) && !Settings.extras(this) && !UserRules.geo(this)) throw new IOException("Рабочая стратегия DPI не найдена. Откройте диагностику.");
            }
            if (!desired) { closeResources(); return; }
            if(Settings.extras(this) || UserRules.geo(this) || Settings.telegram(this)) {
                DataUpdates.module(this).callAttr("materialize",getFilesDir().getPath());
                Strategies.Profile instagram=Strategies.load(this).stream().filter(p->p.id.equals("bye-disorder")).findFirst()
                    .orElseThrow(()->new IOException("Не найден метод для дополнительных сайтов"));
                instagramProcess=launch(instagram,1084,true,true);awaitPort(1084,instagramProcess);
                if(Settings.extras(this) || UserRules.geo(this)) {
                    String detail=Settings.prefs(this).getString("probe_result","");
                    Settings.prefs(this).edit().putString("probe_result",(detail.isEmpty()?"":detail+"\n")+
                        "Дополнительные сайты: прямой маршрут с обходом DPI · свой IP").apply();
                }
            }
            if (!desired) { closeResources(); return; }
            vpnActive=dpiActive || Settings.extras(this) || UserRules.geo(this);
            if (!Python.isStarted()) Python.start(new AndroidPlatform(this));
            engine = Python.getInstance().getModule("android_bridge");
            JSONObject routes=new JSONObject();
            if(Settings.telegram(this))routes.put("telegram_dpi",1084);
            if(dpiActive)routes.put("youtube",1080).put("discord",discordProcess==null?1080:1083);
            if(Settings.extras(this))routes.put("smart_dns",true).put("instagram",1084).put("ai",1084);
            if(UserRules.geo(this))routes.put("smart_dns",true).put("ai",1084);
            routes.put("own_ip",true).put("builtin_extras",Settings.extras(this)).put("geo_domains",UserRules.domains(this,"geo_domains"))
                .put("direct_domains",UserRules.domains(this,"direct_domains"));
            engine.callAttr("start", Settings.secret(this), Settings.telegram(this), vpnActive, getFilesDir().getPath(),routes.toString());
            if (!desired) { closeResources(); return; }
            if (vpnActive) {
                File config = new File(getFilesDir(), "tunnel.yml");
                String yaml = "tunnel:\n  mtu: 1500\n  ipv4: 198.18.0.1\n  ipv6: 'fd00:1::1'\n" +
                    "socks5:\n  address: 127.0.0.1\n  port: 1081\n  udp: 'udp'\n" +
                    "misc:\n  task-stack-size: 86016\n  tcp-buffer-size: 65536\n  max-session-count: 512\n" +
                    "  connect-timeout: 10000\n  tcp-read-write-timeout: 300000\n  udp-read-write-timeout: 60000\n  log-level: error\n";
                try (OutputStream out = new FileOutputStream(config)) { out.write(yaml.getBytes(StandardCharsets.UTF_8)); }
                Builder builder = new Builder().setSession("SorryRKN").setMtu(1500)
                    .addAddress("198.18.0.1", 32).addAddress("fd00:1::1", 128)
                    .addRoute("0.0.0.0", 0).addRoute("::", 0).addDnsServer("8.8.8.8")
                    .addDisallowedApplication(getPackageName()).setBlocking(false);
                if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false);
                tun = builder.establish();
                if (tun == null) throw new IOException("Android не создал VPN-интерфейс");
                int fd = tun.getFd();
                tunnelThread = new Thread(() -> {
                    int code=NativeTunnel.run(config.getPath(), fd);
                    Settings.prefs(this).edit().putInt("native_exit",code).apply();
                }, "tun2socks");
                tunnelThread.start();
            }
            if (!desired) { closeResources(); return; }
            started = true;recovering=false;connectedAt=SystemClock.elapsedRealtime();
            String state=Settings.dpi(this) && !dpiActive ? "partial" : "on";
            publish(state, "");
            foreground(state.equals("partial") ? (vpnActive?"Дополнительные сайты включены · основной метод не найден":"Прокси Telegram включён · DPI не найден") : "Подключение включено");
            if (!Settings.dpi(this)) networkHandle = networkIdentity();
            if (!watchingNetwork) {
                connectivity.registerNetworkCallback(new NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), networks);
                watchingNetwork = true;
            }
            main.postDelayed(health, 3000);
            if(cachedChoice!=null)worker.execute(this::verifyCachedStrategy);
        } catch (Exception | LinkageError e) { if(recovering && desired)recover(e);else fail(e); }
    }

    private Process launch(Strategies.Profile profile, int port, boolean adaptive) throws IOException {
        return launch(profile,port,adaptive,false);
    }
    private Process launch(Strategies.Profile profile, int port, boolean adaptive,boolean instagram) throws IOException {
        List<String> args;
        if (profile.engine.equals("byedpi")) {
            args = new ArrayList<>(Arrays.asList(
                new File(getApplicationInfo().nativeLibraryDir, "libbyedpi.so").getPath(),
                "--ip", "127.0.0.1", "--port", Integer.toString(port), "--max-conn", "512"));
            try {
                com.chaquo.python.PyObject data=Python.getInstance().getModule("bridge_data");
                String value=(instagram ? data.callAttr("extras_args",profile.id,getFilesDir().getPath(),adaptive,
                    UserRules.domains(this,"geo_domains").toString(),UserRules.domains(this,"direct_domains").toString(),Settings.extras(this),Settings.telegram(this)) :
                    data.callAttr("bye_args",profile.id,getFilesDir().getPath(),adaptive)).toString();
                org.json.JSONArray options = new org.json.JSONArray(value);
                for (int i=0; i<options.length(); i++) args.add(options.getString(i));
            } catch (org.json.JSONException e) { throw new IOException("Некорректные параметры ByeDPI", e); }
        } else {
            args = new ArrayList<>(Arrays.asList(
            new File(getApplicationInfo().nativeLibraryDir, "libtpws.so").getPath(),
            "--socks", "--bind-addr=127.0.0.1", "--port=" + port, "--maxconn=512",
            "--hostlist=" + new File(getFilesDir(), "hosts.txt").getPath(),
            "--hostlist-exclude=" + new File(getFilesDir(), "exclude.txt").getPath()));
            args.addAll(profile.args);
        }
        Process process = new ProcessBuilder(args).redirectErrorStream(true).start();
        Thread drain = new Thread(() -> {
            try (InputStream in = process.getInputStream()) {
                byte[] buffer = new byte[4096]; while (in.read(buffer) >= 0) { }
            } catch (IOException ignored) { }
        }, "tpws-output");
        drain.setDaemon(true); drain.start();
        return process;
    }

    private Strategies.Profile chooseStrategy() throws Exception {
        networkHandle = networkIdentity();
        JSONObject prepared = new JSONObject(DataUpdates.module(this).callAttr("materialize", getFilesDir().getPath()).toString());
        String revision = prepared.getJSONObject("commits").toString();
        List<Strategies.Profile> profiles = Strategies.parse(prepared.getJSONArray("profiles"));
        String mode = Settings.prefs(this).getString("strategy", "auto");
        if (!mode.equals("auto")) {
            for (Strategies.Profile p : profiles) if (p.id.equals(mode)) {
                Settings.prefs(this).edit().putString("active_strategy", p.name)
                    .putString("probe_result", "Ручная стратегия · доступ не проверен").apply();
                return p;
            }
            Settings.prefs(this).edit().putString("strategy", "auto").apply();
        }
        if(underlying()==null) {
            Settings.prefs(this).edit().putString("probe_result","Нет доступной сети · проверка DPI отложена").apply();
            return null;
        }
        String key = "last_strategy_" + networkType();choiceNetworkKey=key;
        String last = Settings.prefs(this).getString(key, "");
        boolean force=forceSelection || extended;forceSelection=false;
        if(!force) {
            cachedChoice=StrategyMemory.load(this,key,profiles);
            if(cachedChoice!=null) {
                youtubeProfile=cachedChoice.youtube;discordProfile=cachedChoice.discord;
                String selected=youtubeProfile.id.equals(discordProfile.id)?youtubeProfile.name:
                    "YouTube: "+youtubeProfile.name+" · Discord: "+discordProfile.name;
                Settings.prefs(this).edit().putString("active_strategy",selected)
                    .putString("probe_status","Сохранённый метод · подключаемся")
                    .putString("probe_result","Рабочий метод сохранён для этой сети · проверка в фоне").apply();
                return youtubeProfile;
            }
        }
        if(!extended) {
            List<String> quick=Arrays.asList("bye-disorder","tls","bye-oob","split","bye-tls","bye-fake-8");
            String discordLast=Settings.prefs(this).getString(key+"_discord","");
            profiles.removeIf(p->!quick.contains(p.id) && !p.id.equals(last) && !p.id.equals(discordLast));
            profiles.sort(Comparator.comparingInt(p->quick.contains(p.id)?quick.indexOf(p.id):0));
        }
        profiles.sort((a,b) -> Boolean.compare(!a.id.equals(last), !b.id.equals(last)));
        int bestScore = -1, attempt = 0,discordScore=-1;
        Strategies.Profile discordFallback=null;
        long deadline=SystemClock.elapsedRealtime()+(extended?75000:25000);
        JSONArray reports=new JSONArray();
        PyObject probe = Python.getInstance().getModule("strategy_probe");
        for (Strategies.Profile p : profiles) {
            if (!desired) return null;
            if(SystemClock.elapsedRealtime()>deadline) break;
            String progress = "Проверка " + (++attempt) + "/" + profiles.size() + " · " + p.name;
            Settings.prefs(this).edit().putString("probe_status", progress).apply();
            foreground(progress);
            try {
                tpws = launch(p, 1082, false);
                awaitPort(1082);
                if (!desired) return null;
                JSONObject result = new JSONObject(probe.callAttr("probe", 1082, this).toString());
                if (result.optBoolean("cancelled")) return null;
                result.put("strategy",p.name);
                reports.put(result);
                Settings.prefs(this).edit().putString("probe_report",reports.toString()).apply();
                int score = result.getInt("passed");
                if (score > bestScore) bestScore = score;
                JSONArray targets=result.optJSONArray("targets");
                if(result.optJSONObject("dns")!=null && result.getJSONObject("dns").optBoolean("ok") && targets!=null) {
                    for(int i=0;i<targets.length();i++) {
                        JSONObject target=targets.getJSONObject(i);
                        if(target.optString("name").equals("Discord")) {
                            int quality=(target.optBoolean("api_ok")?1:0)+(target.optBoolean("gateway_ok")?4:0)+(target.optBoolean("cdn_ok")?1:0);
                            if(quality>discordScore && quality>0) { discordScore=quality;discordFallback=p; }
                        }
                        if(!target.optBoolean("ok"))continue;
                        if(target.optString("name").equals("YouTube") && youtubeProfile==null)youtubeProfile=p;
                        if(target.optString("name").equals("Discord") && discordProfile==null)discordProfile=p;
                    }
                }
                if(youtubeProfile!=null && discordProfile!=null) {
                    String selected=youtubeProfile.id.equals(discordProfile.id)?youtubeProfile.name:
                        "YouTube: "+youtubeProfile.name+" · Discord: "+discordProfile.name;
                    Settings.prefs(this).edit().putString(key,youtubeProfile.id).putString(key+"_discord",discordProfile.id)
                        .putString("last_revision",revision).putString("active_strategy",selected)
                        .putString("probe_result","Тестовые адреса: 2/2 · отдельный метод для каждого сервиса").apply();
                    StrategyMemory.save(this,key,youtubeProfile,discordProfile,6);
                    return youtubeProfile;
                }
            } catch (IOException e) {
                JSONObject failure=new JSONObject().put("strategy",p.name).put("stage","native")
                    .put("error",e.getClass().getSimpleName());
                if(tpws!=null && !tpws.isAlive()) failure.put("exit_code",tpws.exitValue());
                reports.put(failure);
                Settings.prefs(this).edit().putString("probe_report",reports.toString()).apply();
            } finally { stopTpws(); }
        }
        if (!desired) return null;
        // A failed Discord gateway/CDN probe must not disable a working
        // YouTube VPN. Keep the best observed Discord candidate with an
        // explicit incomplete status instead of advertising full access.
        if(youtubeProfile!=null || discordProfile!=null) {
            boolean youtubeOk=youtubeProfile!=null,discordOk=discordProfile!=null;
            Strategies.Profile primary=youtubeOk?youtubeProfile:discordProfile;
            if(discordProfile==null)discordProfile=discordFallback;
            String selected="YouTube: "+(youtubeOk?primary.name:"не подтверждён")+" · Discord: "+
                (discordProfile==null?"не подтверждён":discordProfile.name+(discordOk?"":" (частично)"));
            android.content.SharedPreferences.Editor edit=Settings.prefs(this).edit()
                .putString("active_strategy",selected).putString("last_revision",revision)
                .putString("probe_result","Тест YouTube: "+(youtubeOk?"пройден":"не пройден")+
                    " · Discord API/Gateway/CDN: "+(discordOk?"пройдены":"не все пройдены; диагностика в меню"));
            if(youtubeOk)edit.putString(key,youtubeProfile.id);
            if(discordOk)edit.putString(key+"_discord",discordProfile.id);
            edit.apply();
            StrategyMemory.save(this,key,youtubeProfile,discordProfile,discordOk?6:discordScore);
            return primary;
        }
        Settings.prefs(this).edit().putString("active_strategy", "")
            .putString("probe_result", "Рабочий DPI не найден · сайты " + Math.max(0,bestScore) + "/2. Диагностика доступна в меню.").apply();
        return null;
    }

    private JSONObject verifyProfile(Strategies.Profile profile) throws Exception {
        Process candidate=launch(profile,1082,false);
        try {
            awaitPort(1082,candidate);
            return new JSONObject(Python.getInstance().getModule("strategy_probe").callAttr("probe",1082,this).toString());
        } finally {
            candidate.destroy();
            if(!candidate.waitFor(1,TimeUnit.SECONDS))candidate.destroyForcibly();
        }
    }
    private void verifyCachedStrategy() {
        StrategyMemory.Choice saved=cachedChoice;
        String key=choiceNetworkKey;
        if(saved==null||!desired||!started||!networkIdentity().equals(networkHandle))return;
        try {
            JSONObject youtube=verifyProfile(saved.youtube);
            if(!desired||!started||youtube.optBoolean("cancelled"))return;
            JSONObject discord=saved.youtube.id.equals(saved.discord.id)?youtube:verifyProfile(saved.discord);
            if(!desired||!started||discord.optBoolean("cancelled")||!networkIdentity().equals(networkHandle))return;
            boolean youtubeOK=StrategyMemory.youtubeOK(youtube);
            int quality=StrategyMemory.quality(discord);
            JSONArray reports=new JSONArray().put(youtube.put("strategy",saved.youtube.name).put("background",true));
            if(discord!=youtube)reports.put(discord.put("strategy",saved.discord.name).put("background",true));
            Settings.prefs(this).edit().putString("probe_report",reports.toString())
                .putString("probe_result",youtubeOK&&quality>=Math.min(4,saved.discordQuality)?
                    "Сохранённый метод проверен в фоне":"Фоновая проверка: есть ошибки · переподбор доступен в меню").apply();
            if(youtubeOK && quality>=Math.min(4,saved.discordQuality)) {
                StrategyMemory.save(this,key,saved.youtube,saved.discord,quality);return;
            }
            // A failed synthetic target is diagnostic only. Never tear down
            // active Telegram/app sessions to retry a background probe.
        }catch(Exception ignored) { }
    }
    private void recover(Throwable error) {
        if(!desired||destroyed)return;
        publish("starting","");foreground("Восстанавливаем соединение…");
        closeResources();
        if(!desired||destroyed)return;
        recovering=true;recoveryFailures++;
        Settings.prefs(this).edit().putInt("reconnect_count",Settings.prefs(this).getInt("reconnect_count",0)+1).apply();
        main.postDelayed(reconnect,Math.min(60000,1000L << Math.min(recoveryFailures,6)));
    }

    private void retest() {
        if (!desired || !started) return;
        try {
            networkHandle = networkIdentity();
            publish("starting", "");
            closeResources();
            Settings.prefs(this).edit().putString("probe_report","[]").putString("traffic_report","{}")
                .remove("native_exit").apply();
            if(desired) openResources();
        } catch (Exception | LinkageError e) { fail(e); }
    }

    private Network underlying() {
        Network best = null;int bestRank=-1;
        Network active = connectivity.getActiveNetwork();
        for (Network n : connectivity.getAllNetworks()) {
            NetworkCapabilities c = connectivity.getNetworkCapabilities(n);
            if (c == null || c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                || !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
            if (n.equals(active)) return n;
            int rank=(c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)?1000:0)+(c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)?100:0);
            if(rank>bestRank){best=n;bestRank=rank;}
        }
        return best;
    }
    private String networkIdentity() {
        Network n=underlying();
        if(n==null)return "none";
        LinkProperties links=connectivity.getLinkProperties(n);
        List<String> properties=new ArrayList<>();
        if(links!=null) {
            for(LinkAddress address:links.getLinkAddresses())properties.add(address.toString());
            for(InetAddress dns:links.getDnsServers())properties.add(dns.getHostAddress());
            Collections.sort(properties);
        }
        return Long.toString(n.getNetworkHandle())+":"+properties.toString();
    }
    private String networkType() {
        Network n = underlying();
        NetworkCapabilities c = n == null ? null : connectivity.getNetworkCapabilities(n);
        if (c != null && c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "wifi";
        if (c != null && c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "mobile";
        return "other";
    }

    private void stopTpws() {
        if (tpws == null) return;
        tpws.destroy();
        try { if (!tpws.waitFor(1, TimeUnit.SECONDS)) tpws.destroyForcibly(); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); tpws.destroyForcibly(); }
        tpws = null;
    }

    private void awaitPort(int port) throws IOException, InterruptedException {
        awaitPort(port,tpws);
    }
    private void awaitPort(int port,Process process) throws IOException, InterruptedException {
        for (int attempt = 0; attempt < 50 && desired; attempt++) {
            if (!process.isAlive()) throw new IOException("Не удалось запустить сетевой модуль");
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 100);
                return;
            } catch (IOException ignored) { Thread.sleep(100); }
        }
        if (desired) throw new IOException("Локальный модуль zapret не отвечает");
    }

    private void fail(Throwable error) {
        desired = false;
        Settings.prefs(this).edit().putBoolean("desired", false).apply();
        closeResources();
        String detail = error.getMessage();
        if (detail == null || detail.trim().isEmpty()) detail = "Ошибка запуска подключения";
        finishStopped("error", detail, commandId);
    }

    private void closeResources() {
        started = false;
        dpiActive = false;
        vpnActive = false;
        main.removeCallbacks(health);
        main.removeCallbacks(reconnect);
        main.removeCallbacks(networkChanged);
        if (watchingNetwork) {
            connectivity.unregisterNetworkCallback(networks); watchingNetwork = false;
        }
        if (tunnelThread != null) {
            while (tunnelThread.isAlive()) {
                NativeTunnel.quit();
                try { tunnelThread.join(100); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
            }
            tunnelThread = null;
        }
        if (tun != null) { try { tun.close(); } catch (IOException ignored) { } tun = null; }
        if (engine != null) { try { engine.callAttr("stop"); } catch (Exception ignored) { } engine = null; }
        if(instagramProcess!=null) {
            instagramProcess.destroy();
            try { if(!instagramProcess.waitFor(1,TimeUnit.SECONDS))instagramProcess.destroyForcibly(); }
            catch(InterruptedException e) { Thread.currentThread().interrupt();instagramProcess.destroyForcibly(); }
            instagramProcess=null;
        }
        if(discordProcess!=null) {
            discordProcess.destroy();
            try { if(!discordProcess.waitFor(1,TimeUnit.SECONDS))discordProcess.destroyForcibly(); }
            catch(InterruptedException e) { Thread.currentThread().interrupt();discordProcess.destroyForcibly(); }
            discordProcess=null;
        }
        stopTpws();
    }

    private void finishStopped(String state, String error, int startId) {
        main.post(() -> {
            if (desired || destroyed) return;
            publish(state, error);
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelfResult(startId);
        });
    }
    private void publish(String state, String error) {
        Settings.prefs(this).edit().putString("state", state).putString("error", error).putBoolean("vpn_active",vpnActive).apply();
        TileService.requestListeningState(this, new ComponentName(this, BridgeTile.class));
    }
    private void foreground(String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel("connection", "Подключение", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, BridgeService.class).setAction(STOP), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification notification = new Notification.Builder(this, "connection")
            .setSmallIcon(R.drawable.ic_bridge).setContentTitle("SorryRKN").setContentText(text)
            .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
            .addAction(new Notification.Action.Builder(null, "Выключить", stop).build()).build();
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(1, notification);
    }
    @Override public void onRevoke() {
        desired = false;
        Settings.prefs(this).edit().putBoolean("desired", false).apply();
        worker.execute(() -> { closeResources(); finishStopped("off", "", commandId); });
    }
    @Override public void onDestroy() {
        desired = false; destroyed = true;
        worker.execute(this::closeResources);
        worker.shutdown();
        if (!Settings.state(this).equals("error")) Settings.prefs(this).edit().putString("state", "off").apply();
        TileService.requestListeningState(this, new ComponentName(this, BridgeTile.class));
        super.onDestroy();
    }
}
