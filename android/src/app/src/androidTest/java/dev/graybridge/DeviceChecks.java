package dev.graybridge;

import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.content.*;
import android.os.Bundle;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

/** Runs only in the separate test APK, never packaged in the user APK. */
public class DeviceChecks extends Instrumentation {
    private Bundle arguments;
    @Override public void onCreate(Bundle args) { super.onCreate(args); arguments=args; start(); }
    @Override public void onStart() {
        Bundle report = new Bundle();
        try {
            Context target = getTargetContext();
            if(arguments!=null && Boolean.parseBoolean(arguments.getString("startupUpdatesChecks","false"))) {
                StartupUpdateChecks.run(this,target,report);report.putString("result","PASS");finish(0,report);return;
            }
            if (!Python.isStarted()) Python.start(new AndroidPlatform(target));
            if(arguments!=null && Boolean.parseBoolean(arguments.getString("publicServiceChecks","false"))) {
                boolean passed=publicServiceChecks(target,report);
                report.putString("result",passed?"PASS":"PARTIAL: public service checks failed");finish(passed?0:1,report);return;
            }
            if(arguments!=null && Boolean.parseBoolean(arguments.getString("telegramVerifiedChecks","false"))) {
                telegramVerifiedChecks(target,report);
                report.putString("result","PASS");finish(0,report);return;
            }
            if(arguments!=null && Boolean.parseBoolean(arguments.getString("telegramNativeChecks","false"))) {
                com.chaquo.python.PyObject globals=Python.getInstance().getModule("builtins").callAttr("dict");
                try(java.io.InputStream input=getContext().getAssets().open("telegram_native_check.py")) {
                    Python.getInstance().getModule("builtins").callAttr("exec",readUtf8(input),globals);
                }
                com.chaquo.python.PyObject result=Python.getInstance().getModule("asyncio").callAttr("run",
                    globals.callAttr("__getitem__","run").call());
                report.putString("telegram_native",Python.getInstance().getModule("json").callAttr("dumps",result).toString());
                report.putString("result","PASS");finish(0,report);return;
            }
            if(arguments!=null && arguments.getString("telegramRouteChecks")!=null) {
                com.chaquo.python.PyObject globals=Python.getInstance().getModule("builtins").callAttr("dict");
                try(java.io.InputStream input=getContext().getAssets().open("telegram_route_check.py")) {
                    Python.getInstance().getModule("builtins").callAttr("exec",readUtf8(input),globals);
                }
                com.chaquo.python.PyObject result=Python.getInstance().getModule("asyncio").callAttr("run",
                    globals.callAttr("__getitem__","run").call(arguments.getString("telegramRouteChecks")));
                report.putString("telegram_routes_check",Python.getInstance().getModule("json").callAttr("dumps",result).toString());
                report.putString("result","PASS");finish(0,report);return;
            }
            if(arguments!=null && arguments.getString("telegramFrontingChecks")!=null) {
                com.chaquo.python.PyObject globals=Python.getInstance().getModule("builtins").callAttr("dict");
                try(java.io.InputStream input=getContext().getAssets().open("telegram_fronting_check.py")) {
                    Python.getInstance().getModule("builtins").callAttr("exec",readUtf8(input),globals);
                }
                String pem;
                try(java.io.InputStream input=new java.io.FileInputStream(arguments.getString("telegramFrontingChecks"))) {
                    pem=readUtf8(input);
                }
                com.chaquo.python.PyObject result=Python.getInstance().getModule("asyncio").callAttr("run",
                    globals.callAttr("__getitem__","run").call(pem));
                report.putString("telegram_fronting",Python.getInstance().getModule("json").callAttr("dumps",result).toString());
                report.putString("result","PASS");finish(0,report);return;
            }
            if(arguments!=null && arguments.getString("telegramDpiChecks")!=null) {
                telegramDpiChecks(target,report,arguments.getString("telegramDpiChecks"));
                report.putString("result","PASS");finish(0,report);return;
            }
            if(arguments!=null && arguments.getString("telegramWireChecks")!=null) {
                String directory=arguments.getString("telegramWireChecks");
                com.chaquo.python.PyObject globals=Python.getInstance().getModule("builtins").callAttr("dict");
                try(java.io.InputStream input=getContext().getAssets().open("telegram_wire_check.py")) {
                    Python.getInstance().getModule("builtins").callAttr("exec",readUtf8(input),globals);
                }
                com.chaquo.python.PyObject result=Python.getInstance().getModule("asyncio").callAttr("run",
                    globals.callAttr("__getitem__","run").call(directory+"/cert.pem",directory+"/key.pem"));
                report.putString("telegram_wire",Python.getInstance().getModule("json").callAttr("dumps",result).toString());
                report.putString("result","PASS");finish(0,report);return;
            }
            if(arguments!=null && Boolean.parseBoolean(arguments.getString("telegramMediaChecks","false"))) {
                telegramMediaChecks(target,report);report.putString("result","PASS");finish(0,report);return;
            }
            if(arguments!=null && Boolean.parseBoolean(arguments.getString("networkChecks","false"))) {
                networkChecks(target,report);report.putString("result","PASS");finish(0,report);return;
            }
            if(arguments!=null && Boolean.parseBoolean(arguments.getString("recoveryChecks","false"))) {
                recoveryChecks(target,report);report.putString("result","PASS");finish(0,report);return;
            }
            if(arguments!=null && Boolean.parseBoolean(arguments.getString("userRulesChecks","false"))) {
                userRulesChecks(target,report);report.putString("result","PASS");finish(0,report);return;
            }
            if(arguments!=null && Boolean.parseBoolean(arguments.getString("cryptoBench","false"))) {
                com.chaquo.python.PyObject globals=Python.getInstance().getModule("builtins").callAttr("dict");
                try(java.io.InputStream input=getContext().getAssets().open("crypto_benchmark.py")) {
                    Python.getInstance().getModule("builtins").callAttr("exec",readUtf8(input),globals);
                }
                String value=globals.callAttr("__getitem__","run").call().toString();
                report.putString("benchmark",value); report.putString("result","PASS"); finish(0,report); return;
            }
            Python.getInstance().getModule("builtins").callAttr("exec",
                "from proxy._aes import Cipher, algorithms, modes\n" +
                "key=bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')\n" +
                "iv=bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')\n" +
                "plain=bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51')\n" +
                "expected=bytes.fromhex('874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff')\n" +
                "cipher=Cipher(algorithms.AES(key),modes.CTR(iv)).encryptor()\n" +
                "actual=cipher.update(plain[:7])+cipher.update(plain[7:19])+cipher.update(plain[19:])\n" +
                "assert actual==expected, 'Android AES-CTR streaming mismatch'\n",
                Python.getInstance().getModule("builtins").callAttr("dict"));
            report.putString("crypto", "PASS: NIST AES-CTR across unaligned updates");
            if(arguments!=null && arguments.getString("updateChecks")!=null) {
                String path=arguments.getString("updateChecks");
                AppUpdates.verifyArchive(target,new java.io.File(path+"/good.apk"),BuildConfig.VERSION_CODE);
                for(String name:new String[]{"wrong-key.apk","corrupt.apk"}) {
                    try { AppUpdates.verifyArchive(target,new java.io.File(path+"/"+name),BuildConfig.VERSION_CODE); throw new AssertionError("Accepted "+name); }
                    catch(java.io.IOException expected) { }
                }
                try {AppUpdates.verifyArchive(target,new java.io.File(path+"/good.apk"),BuildConfig.VERSION_CODE+1);throw new AssertionError("Accepted wrong version");}
                catch(java.io.IOException expected) { }
                org.json.JSONObject manifest=new org.json.JSONObject().put("versionCode",9).put("versionName","0.9.0")
                    .put("url","https://example.com/update.apk").put("sha256",new String(new char[64]).replace('\0','a')).put("size",20_000_000);
                new AppUpdates.Release(manifest);
                for(String invalid:new String[]{"http://example.com/x","file:///x","https://user:secret@example.com/x"}) {
                    try {AppUpdates.safeUrl(invalid);throw new AssertionError("Accepted "+invalid);}catch(java.io.IOException expected) { }
                }
                manifest.put("size",AppUpdates.MAX_APK+1);
                try {new AppUpdates.Release(manifest);throw new AssertionError("Accepted oversized manifest");}catch(java.io.IOException expected) { }
                manifest.put("size",100).put("sha256","invalid");
                try {new AppUpdates.Release(manifest);throw new AssertionError("Accepted malformed digest");}catch(java.io.IOException expected) { }
                report.putString("updates","PASS: matching signature; rejected wrong signature/version/corrupt APK, insecure URLs and malformed manifests");
                report.putString("result","PASS");finish(0,report);return;
            }
            String directory = target.getFilesDir().getPath();
            DataUpdates.module(target).callAttr("materialize",directory);
            java.util.List<Strategies.Profile> profiles = Strategies.load(target);
            if(profiles.size()<6) throw new AssertionError("Incomplete strategy catalog");
            // Exercise the Java/Python cancellation bridge without external connectivity.
            DataUpdates.Control cancelled = new DataUpdates.Control(); cancelled.cancel();
            String probe = Python.getInstance().getModule("strategy_probe").callAttr("probe",1082,cancelled).toString();
            if(!new org.json.JSONObject(probe).optBoolean("cancelled")) throw new AssertionError("Probe cancellation failed");
            report.putString("data","PASS: bundled snapshot, strategy catalog, Java/Python cancellation");
            if(arguments!=null && Boolean.parseBoolean(arguments.getString("dataPath","false"))) {
                dataPath(target,report,arguments.getString("strategy","split"));
                report.putString("result","PASS"); finish(0,report); return;
            }
            String previous = Settings.prefs(target).getString("strategy","auto");
            boolean updates = Settings.prefs(target).getBoolean("auto_updates",true);
            boolean previousExtras=Settings.extras(target);
            boolean previousDpi=Settings.dpi(target),previousTelegram=Settings.telegram(target);
            // Lifecycle checks must not depend on the test emulator's Internet route.
            Settings.prefs(target).edit().putString("strategy","split").putBoolean("auto_updates",false).putBoolean("extra_sites",false).putBoolean("dpi",true).putBoolean("telegram",true).apply();
            // Appops ACTIVATE_VPN must have been granted on this test emulator.
            target.startActivity(new Intent(target,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            for(int cycle=0; cycle<2; cycle++) {
                Settings.prefs(target).edit().putString("strategy",cycle==0 ? "split" : "bye-disorder").apply();
                BridgeService.start(target);
                waitFor(target,"on",45000);
                if(!Python.getInstance().getModule("android_bridge").callAttr("is_running").toBoolean())
                    throw new AssertionError("Python engine not running");
                BridgeService.stop(target);
                waitFor(target,"off",20000);
                if(Python.getInstance().getModule("android_bridge").callAttr("is_running").toBoolean())
                    throw new AssertionError("Python engine remained active after stop");
                if(Python.getInstance().getModule("builtins").callAttr("eval",
                    "bool(__import__('android_bridge')._thread and __import__('android_bridge')._thread.is_alive())",
                    Python.getInstance().getModule("builtins").callAttr("dict")).toBoolean())
                    throw new AssertionError("Python worker survived completed stop");
            }
            report.putString("lifecycle","PASS: tpws and adaptive ByeDPI VPN + Telegram start/stop");
            // Force all HTTP probes to fail. Production code must keep Telegram
            // running without starting an unverified DPI VPN or claiming success.
            com.chaquo.python.PyObject probeGlobals=Python.getInstance().getModule("builtins").callAttr("dict");
            Python.getInstance().getModule("builtins").callAttr("exec",
                "import strategy_probe\n_saved_probe=strategy_probe.probe\n"+
                "strategy_probe.probe=lambda port,control: '{\"passed\":0,\"total\":2,\"complete\":false,\"targets\":[]}'\n",
                probeGlobals);
            try {
                clearStrategyMemory(target);Settings.prefs(target).edit().putString("strategy","auto").apply();
                BridgeService.start(target); waitFor(target,"partial",15000);
                Thread.sleep(3500);
                if(!Settings.state(target).equals("partial")) throw new AssertionError("Telegram fallback was not stable");
                try(java.net.Socket socket=new java.net.Socket("127.0.0.1",1443)) { }
                for(int port:new int[]{1080,1081,1082}) {
                    try(java.net.Socket socket=new java.net.Socket("127.0.0.1",port)) {
                        throw new AssertionError("Unverified DPI listener remained active: "+port);
                    } catch(java.io.IOException expected) { }
                }
                BridgeService.stop(target); waitFor(target,"off",15000);
                report.putString("fallback","PASS: failed selection keeps Telegram only, no DPI proxy listeners");
            } finally {
                Python.getInstance().getModule("builtins").callAttr("exec",
                    "strategy_probe.probe=_saved_probe\n",
                    probeGlobals);
            }
            Settings.prefs(target).edit().putString("strategy","auto").apply();
            BridgeService.start(target);
            long deadline=System.currentTimeMillis()+20000;
            while(!Settings.prefs(target).getString("probe_status","").startsWith("Проверка ")) {
                if(System.currentTimeMillis()>deadline) throw new AssertionError("Auto selection did not start");
                Thread.sleep(100);
            }
            Thread.sleep(300);
            BridgeService.stop(target);
            waitFor(target,"off",15000);
            for(int port: new int[]{1080,1082,1443}) {
                try(java.net.Socket socket=new java.net.Socket()) {
                    socket.connect(new java.net.InetSocketAddress("127.0.0.1",port),100);
                    throw new AssertionError("Port remained open after cancellation: "+port);
                } catch(java.io.IOException expected) { }
            }
            report.putString("selection","PASS: cancel auto selection and release all proxy ports");
            Settings.prefs(target).edit().putString("strategy",previous).putBoolean("auto_updates",updates).putBoolean("extra_sites",previousExtras).putBoolean("dpi",previousDpi).putBoolean("telegram",previousTelegram).apply();
            report.putString("result","PASS");
            finish(0,report);
        } catch(Throwable e) {
            report.putString("result","FAIL: "+e);
            if(Python.isStarted()) {
                try {
                    com.chaquo.python.PyObject traceGlobals=Python.getInstance().getModule("builtins").callAttr("dict");
                    try(java.io.InputStream input=getContext().getAssets().open("python_failure_snapshot.py")) {
                        Python.getInstance().getModule("builtins").callAttr("exec",readUtf8(input),traceGlobals);
                    }
                    com.chaquo.python.PyObject snapshot=traceGlobals.callAttr("__getitem__","capture").call();
                    report.putString("python_failure",Python.getInstance().getModule("json").callAttr("dumps",snapshot).toString());
                } catch(Throwable traceError) {
                    report.putString("python_failure","Snapshot failed: "+traceError.getClass().getName());
                }
            }
            finish(1,report);
        }
    }
    private void clearStrategyMemory(Context target) {
        android.content.SharedPreferences.Editor edit=Settings.prefs(target).edit();
        for(String key:Settings.prefs(target).getAll().keySet())if(key.startsWith("last_strategy_"))edit.remove(key);
        edit.apply();
    }
    private void shell(String command) throws Exception {
        try(android.os.ParcelFileDescriptor fd=getUiAutomation().executeShellCommand(command);
            java.io.FileInputStream input=new java.io.FileInputStream(fd.getFileDescriptor())) {readUtf8(input);}
    }
    private void telegramVerifiedChecks(Context target,Bundle report) throws Exception {
        android.content.SharedPreferences prefs=Settings.prefs(target);
        java.util.Map<String,?> previous=new java.util.HashMap<>(prefs.getAll());
        try {
            BridgeService.stop(target);waitFor(target,"off",20000);
            prefs.edit().putBoolean("dpi",false).putBoolean("extra_sites",false).putBoolean("telegram",true)
                .putBoolean("telegram_relay",true).putBoolean("ai_relay",false)
                .putString("geo_domains","").putString("direct_domains","").putBoolean("auto_updates",false)
                .putLong("apk_update_checked",System.currentTimeMillis()).apply();
            startActivitySync(new Intent(target,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));waitForIdleSync();
            BridgeService.start(target);waitForEngine(target,30000);
            // Service startup must launch its packaged native ByeDPI, even in Telegram-only mode.
            try(java.net.Socket socket=new java.net.Socket()) {
                socket.connect(new java.net.InetSocketAddress("127.0.0.1",1084),1000);
            }
            com.chaquo.python.PyObject globals=Python.getInstance().getModule("builtins").callAttr("dict");
            try(java.io.InputStream input=getContext().getAssets().open("telegram_verified_check.py")) {
                Python.getInstance().getModule("builtins").callAttr("exec",readUtf8(input),globals);
            }
            String value=globals.callAttr("__getitem__","run").call(Settings.secret(target)).toString();
            report.putString("telegram_verified",value);
            org.json.JSONObject result=new org.json.JSONObject(value);
            if(!result.optString("result").equals("PASS") || result.optInt("passed")!=10 || !result.optBoolean("engine_preserved"))
                throw new AssertionError("Live Telegram validation failed: "+value);
            report.putString("observed_service_state",Settings.state(target));
        } finally {
            try {
                BridgeService.stop(target);waitFor(target,"off",20000);
                if(Python.getInstance().getModule("android_bridge").callAttr("is_running").toBoolean())
                    throw new AssertionError("Telegram engine remained active after verified check");
                for(int port:new int[]{1084,1443}) {
                    try(java.net.Socket socket=new java.net.Socket()) {
                        socket.connect(new java.net.InetSocketAddress("127.0.0.1",port),100);
                        throw new AssertionError("Check listener remained open: "+port);
                    } catch(java.io.IOException expected) { }
                }
                report.putString("telegram_verified_cleanup","PASS: engine stopped and ports closed");
            } finally {restoreCheckPreferences(prefs,previous);}
        }
    }
    @android.annotation.SuppressLint("UnspecifiedRegisterReceiverFlag")
    private boolean publicServiceChecks(Context target,Bundle report) throws Exception {
        android.content.SharedPreferences prefs=Settings.prefs(target);
        java.util.Map<String,?> previous=new java.util.HashMap<>(prefs.getAll());
        java.util.concurrent.CountDownLatch ready=new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicReference<String> detail=new java.util.concurrent.atomic.AtomicReference<>();
        String token=java.util.UUID.randomUUID().toString();
        BroadcastReceiver receiver=new BroadcastReceiver() {
            @Override public void onReceive(Context context,Intent intent) {
                if(!token.equals(intent.getStringExtra("probeToken")))return;
                detail.set(intent.getStringExtra("publicServices"));ready.countDown();
            }
        };
        IntentFilter filter=new IntentFilter("dev.graybridge.probe.RESULT");
        if(android.os.Build.VERSION.SDK_INT>=33)target.registerReceiver(receiver,filter,Context.RECEIVER_EXPORTED);
        else target.registerReceiver(receiver,filter);
        try {
            BridgeService.stop(target);waitFor(target,"off",20000);
            prefs.edit().putBoolean("dpi",true).putBoolean("telegram",true).putBoolean("extra_sites",true)
                .putBoolean("ai_relay",true).putBoolean("telegram_relay",true).putString("strategy","auto")
                .putString("geo_domains","").putString("direct_domains","").putBoolean("auto_updates",false)
                .putLong("apk_update_checked",System.currentTimeMillis()).apply();
            startActivitySync(new Intent(target,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));waitForIdleSync();
            BridgeService.start(target);waitForEngine(target,110000);
            // Let the existing bounded background selector finish before testing new user sockets.
            long healthDeadline=android.os.SystemClock.elapsedRealtime()+20000;
            org.json.JSONObject diagnostics;
            do {
                diagnostics=new org.json.JSONObject(Python.getInstance().getModule("android_bridge").callAttr("diagnostics").toString());
                org.json.JSONObject ai=diagnostics.optJSONObject("ai_route_check");
                if(ai!=null && !ai.optString("state").equals("checking"))break;
                Thread.sleep(200);
            } while(android.os.SystemClock.elapsedRealtime()<healthDeadline);
            report.putString("public_services_startup",new org.json.JSONObject().put("state",Settings.state(target))
                .put("active_strategy",prefs.getString("active_strategy",""))
                .put("ai_route_check",diagnostics.optJSONObject("ai_route_check")).toString());
            target.startActivity(new Intent().setComponent(new ComponentName("dev.graybridge.probe","dev.graybridge.probe.ProbeActivity"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TASK)
                .putExtra("publicServiceChecks",true).putExtra("requireVpn",true)
                .putExtra("callbackPackage",target.getPackageName()).putExtra("probeToken",token));
            if(!ready.await(65000,java.util.concurrent.TimeUnit.MILLISECONDS))throw new AssertionError("No public service probe response within 65 s");
            if(detail.get()==null)throw new AssertionError("Missing public service report");
            report.putString("public_services",detail.get());
            org.json.JSONObject value=new org.json.JSONObject(detail.get());
            if(!value.optBoolean("vpn_active_for_probe_uid") || value.optInt("total")!=7)throw new AssertionError("Invalid separate UID public report");
            report.putString("public_services_routing",Python.getInstance().getModule("android_bridge").callAttr("diagnostics").toString());
            long[] counters=NativeTunnel.stats();
            report.putString("public_services_tunnel",new org.json.JSONObject().put("tx_bytes",counters[1]).put("rx_bytes",counters[3]).toString());
            if(!Python.getInstance().getModule("android_bridge").callAttr("is_running").toBoolean())throw new AssertionError("Public checks stopped the engine");
            return value.optString("result").equals("PASS") && value.optInt("passed")==7;
        } finally {
            target.unregisterReceiver(receiver);
            try {
                BridgeService.stop(target);waitFor(target,"off",20000);
                for(int port:new int[]{1080,1081,1082,1083,1084,1443}) {
                    try(java.net.Socket socket=new java.net.Socket()) {
                        socket.connect(new java.net.InetSocketAddress("127.0.0.1",port),100);
                        throw new AssertionError("Public check listener remained open: "+port);
                    } catch(java.io.IOException expected) { }
                }
                report.putString("public_services_cleanup","PASS: engine stopped and ports closed");
            } finally {restoreCheckPreferences(prefs,previous);}
        }
    }
    private void restoreCheckPreferences(android.content.SharedPreferences prefs,java.util.Map<String,?> previous) {
        android.content.SharedPreferences.Editor edit=prefs.edit().clear();
        for(java.util.Map.Entry<String,?> entry:previous.entrySet()) {
            Object value=entry.getValue();String key=entry.getKey();
            if(value instanceof String)edit.putString(key,(String)value);
            else if(value instanceof Boolean)edit.putBoolean(key,(Boolean)value);
            else if(value instanceof Integer)edit.putInt(key,(Integer)value);
            else if(value instanceof Long)edit.putLong(key,(Long)value);
            else if(value instanceof Float)edit.putFloat(key,(Float)value);
            else if(value instanceof java.util.Set) {
                java.util.Set<String> restored=new java.util.HashSet<>();
                for(Object item:(java.util.Set<?>)value)if(item instanceof String)restored.add((String)item);
                edit.putStringSet(key,restored);
            }
        }
        edit.putString("state","off").putBoolean("desired",false).apply();
    }
    private void waitForEngine(Context target,long timeout) throws InterruptedException {
        long end=System.currentTimeMillis()+timeout;
        while(System.currentTimeMillis()<end) {
            String state=Settings.state(target);
            if((state.equals("on")||state.equals("partial")) &&
                Python.getInstance().getModule("android_bridge").callAttr("is_running").toBoolean())return;
            if(state.equals("error"))throw new AssertionError(Settings.prefs(target).getString("error","unknown"));
            Thread.sleep(100);
        }
        throw new AssertionError("Engine did not start: "+Settings.state(target));
    }
    private void telegramMediaChecks(Context target,Bundle report) throws Exception {
        android.content.SharedPreferences prefs=Settings.prefs(target);
        java.util.Map<String,?> previous=new java.util.HashMap<>(prefs.getAll());
        com.chaquo.python.PyObject globals=Python.getInstance().getModule("builtins").callAttr("dict");
        Python.getInstance().getModule("builtins").callAttr("exec",
            "import asyncio\nfrom proxy import raw_websocket\n_saved_connect=raw_websocket.RawWebSocket.connect\n"+
            "async def pending_connect(*args,**kwargs):await asyncio.sleep(120)\n"+
            "raw_websocket.RawWebSocket.connect=staticmethod(pending_connect)\n",globals);
        try {
            prefs.edit().putBoolean("dpi",false).putBoolean("telegram",true).putBoolean("extra_sites",false)
                .putString("geo_domains","").putString("direct_domains","").putBoolean("auto_updates",false)
                .putLong("apk_update_checked",System.currentTimeMillis()).apply();
            startActivitySync(new Intent(target,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));waitForIdleSync();
            BridgeService.start(target);waitFor(target,"on",30000);
            String thread=Python.getInstance().getModule("builtins").callAttr("id",Python.getInstance().getModule("android_bridge").get("_thread")).toString();
            int reconnects=prefs.getInt("reconnect_count",0);
            try(java.io.InputStream input=getContext().getAssets().open("telegram_media_checks.py")) {
                Python.getInstance().getModule("builtins").callAttr("exec",readUtf8(input),globals);
            }
            String value=globals.callAttr("__getitem__","run").call().toString();
            org.json.JSONObject details=new org.json.JSONObject(value);
            if(!details.getString("result").equals("PASS"))throw new AssertionError(value);
            if(!Settings.state(target).equals("on")||prefs.getInt("reconnect_count",0)!=reconnects)
                throw new AssertionError("Media recovery restarted whole connection");
            if(!Python.getInstance().getModule("builtins").callAttr("id",Python.getInstance().getModule("android_bridge").get("_thread")).toString().equals(thread))
                throw new AssertionError("Media recovery replaced network engine");
            try(java.net.Socket socket=new java.net.Socket("127.0.0.1",1443)) { }
            report.putString("telegram_media",value);
            report.putString("isolation","PASS: original service/engine remained on, Telegram listener available, no reconnect");
        } finally {
            BridgeService.stop(target);waitFor(target,"off",20000);
            Python.getInstance().getModule("builtins").callAttr("exec",
                "raw_websocket.RawWebSocket.connect=staticmethod(_saved_connect)\n",globals);
            android.content.SharedPreferences.Editor edit=prefs.edit().clear();
            for(java.util.Map.Entry<String,?> e:previous.entrySet()) {
                Object v=e.getValue();
                if(v instanceof String)edit.putString(e.getKey(),(String)v);
                else if(v instanceof Boolean)edit.putBoolean(e.getKey(),(Boolean)v);
                else if(v instanceof Long)edit.putLong(e.getKey(),(Long)v);
                else if(v instanceof Integer)edit.putInt(e.getKey(),(Integer)v);
                else if(v instanceof Float)edit.putFloat(e.getKey(),(Float)v);
            }
            edit.putString("state","off").putBoolean("desired",false).apply();
        }
    }
    private void networkChecks(Context target,Bundle report) throws Exception {
        android.content.SharedPreferences prefs=Settings.prefs(target);
        prefs.edit().putString("strategy","split").putBoolean("dpi",false).putBoolean("telegram",true)
            .putBoolean("extra_sites",false).putString("geo_domains","").putBoolean("auto_updates",false)
            .putLong("apk_update_checked",System.currentTimeMillis()).apply();
        startActivitySync(new Intent(target,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));waitForIdleSync();
        try {
            for(boolean dpi:new boolean[]{false,true}) {
                prefs.edit().putBoolean("dpi",dpi).apply();
                BridgeService.start(target);waitFor(target,"on",30000);
                int count=prefs.getInt("network_reconnect_count",0);
                shell("svc data disable");
                long deadline=System.currentTimeMillis()+20000;
                while(prefs.getInt("network_reconnect_count",0)<=count) {
                    if(System.currentTimeMillis()>deadline)throw new AssertionError("Network loss ignored in "+(dpi?"manual DPI":"Telegram-only"));
                    Thread.sleep(100);
                }
                waitFor(target,"on",20000);int lost=prefs.getInt("network_reconnect_count",0);
                shell("svc data enable");deadline=System.currentTimeMillis()+20000;
                while(prefs.getInt("network_reconnect_count",0)<=lost) {
                    if(System.currentTimeMillis()>deadline)throw new AssertionError("Network return ignored");
                    Thread.sleep(100);
                }
                waitFor(target,"on",20000);
                if(!Python.getInstance().getModule("android_bridge").callAttr("is_running").toBoolean())throw new AssertionError("Network engine failed after network switch");
                BridgeService.stop(target);waitFor(target,"off",20000);
            }
            report.putString("network","PASS: actual cellular network loss/return recovered in Telegram-only and manual DPI modes");
        } finally {shell("svc data enable");BridgeService.stop(target);waitFor(target,"off",20000);}
    }
    private void recoveryChecks(Context target,Bundle report) throws Exception {
        android.content.SharedPreferences prefs=Settings.prefs(target);
        java.util.Map<String,?> previous=new java.util.HashMap<>(prefs.getAll());
        DataUpdates.module(target).callAttr("materialize",target.getFilesDir().getPath());
        java.util.List<Strategies.Profile> profiles=Strategies.load(target);
        Strategies.Profile youtube=profiles.stream().filter(p->p.id.equals("split")).findFirst().get();
        Strategies.Profile discord=profiles.stream().filter(p->p.id.equals("bye-disorder")).findFirst().get();
        for(String type:new String[]{"wifi","mobile","other"})StrategyMemory.save(target,"last_strategy_"+type,youtube,discord,6);
        prefs.edit().putString("last_revision","changed-unrelated-github-data").apply();
        if(StrategyMemory.load(target,"last_strategy_mobile",profiles)==null)throw new AssertionError("Data revision discarded valid choices");
        org.json.JSONObject changed=new org.json.JSONObject().put("id",youtube.id).put("name",youtube.name)
            .put("engine",youtube.engine).put("args",new org.json.JSONArray().put("--changed"));
        java.util.List<Strategies.Profile> altered=new java.util.ArrayList<>(profiles);
        altered.removeIf(p->p.id.equals(youtube.id));altered.add(new Strategies.Profile(changed));
        if(StrategyMemory.load(target,"last_strategy_mobile",altered)!=null)throw new AssertionError("Changed method arguments used stale cache");
        prefs.edit().putString("strategy","auto").putBoolean("auto_updates",false).putBoolean("dpi",true)
            .putBoolean("telegram",true).putBoolean("extra_sites",false).putString("geo_domains","").putString("direct_domains","")
            .putLong("apk_update_checked",System.currentTimeMillis()).apply();
        startActivitySync(new Intent(target,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));waitForIdleSync();
        com.chaquo.python.PyObject globals=Python.getInstance().getModule("builtins").callAttr("dict");
        Python.getInstance().getModule("builtins").callAttr("exec",
            "import strategy_probe,time,json,asyncio\nfrom proxy import raw_websocket\n_saved_connect=raw_websocket.RawWebSocket.connect\n"+
            "async def pending_connect(*args,**kwargs):await asyncio.sleep(60)\n"+
            "raw_websocket.RawWebSocket.connect=staticmethod(pending_connect)\n_saved_probe=strategy_probe.probe\n"+
            "def slow_probe(port,control):\n"+
            "    deadline=time.monotonic()+5\n"+
            "    while time.monotonic()<deadline:\n"+
            "        if not control.keepRunning():return json.dumps({'cancelled':True})\n"+
            "        time.sleep(.05)\n"+
            "    return json.dumps({'passed':2,'total':2,'complete':True,'targets':[{'name':'YouTube','ok':True},{'name':'Discord','ok':True,'api_ok':True,'gateway_ok':True,'cdn_ok':True}]})\n"+
            "strategy_probe.probe=slow_probe\n",globals);
        try {
            long began=android.os.SystemClock.elapsedRealtime();
            BridgeService.start(target);waitFor(target,"on",30000);
            if(!prefs.getString("probe_report","[]").equals("[]"))throw new AssertionError("Startup waited for network tests");
            long coldElapsed=android.os.SystemClock.elapsedRealtime()-began;
            report.putString("cold_start_ms",Long.toString(coldElapsed));
            BridgeService.stop(target);waitFor(target,"off",20000);
            began=android.os.SystemClock.elapsedRealtime();
            BridgeService.start(target);waitFor(target,"on",4000);
            long elapsed=android.os.SystemClock.elapsedRealtime()-began;
            if(elapsed>=4000)throw new AssertionError("Cached startup waited for full probe: "+elapsed);
            report.putString("cached_start","PASS: connected in "+elapsed+" ms (cold "+coldElapsed+" ms), probe takes 5000 ms per method");
            Python.getInstance().getModule("builtins").callAttr("exec",
                "import android_bridge\n_saved_start=android_bridge.start\n_start_calls=0\n"+
                "def counted_start(*args,**kwargs):\n"+
                "    global _start_calls\n    _start_calls+=1\n    return _saved_start(*args,**kwargs)\n"+
                "android_bridge.start=counted_start\n"+
                "strategy_probe.probe=lambda port,control: json.dumps({'passed':0,'total':2,'complete':False,'targets':[{'name':'YouTube','ok':False},{'name':'Discord','ok':False}]})\n",globals);
            Thread.sleep(23000); // Past the removed 10 s retry and complete failed probes.
            if(!Settings.state(target).equals("on"))throw new AssertionError("Failed background probe disconnected apps");
            int restarts=globals.callAttr("__getitem__","_start_calls").toInt();
            if(restarts!=0)throw new AssertionError("Failed background probe restarted working engine: "+restarts);
            if(!prefs.getString("probe_result","").contains("есть ошибки"))throw new AssertionError("Failed probe not recorded");
            try(java.net.Socket socket=new java.net.Socket("127.0.0.1",1443)) { }
            report.putString("background_failure","PASS: failed background targets recorded; 23 s, no engine restart, Telegram available");
            int count=prefs.getInt("reconnect_count",0);
            Python.getInstance().getModule("android_bridge").callAttr("stop");
            long deadline=System.currentTimeMillis()+25000;
            while(prefs.getInt("reconnect_count",0)==count||!Settings.state(target).equals("on")) {
                if(System.currentTimeMillis()>deadline)throw new AssertionError("Dead engine did not recover: "+Settings.state(target));
                Thread.sleep(100);
            }
            if(!Python.getInstance().getModule("android_bridge").callAttr("is_running").toBoolean())throw new AssertionError("Recovered engine not running");
            try(java.net.Socket socket=new java.net.Socket("127.0.0.1",1443)) { }
            report.putString("recovery","PASS: killed network engine restored automatically; Telegram listener available");
            report.putString("memory","PASS: isolated network choices; unrelated revision preserved, changed args rejected");
        } finally {
            BridgeService.stop(target);waitFor(target,"off",20000);
            Python.getInstance().getModule("builtins").callAttr("exec","strategy_probe.probe=_saved_probe\nraw_websocket.RawWebSocket.connect=staticmethod(_saved_connect)\nif '_saved_start' in globals():android_bridge.start=_saved_start\n",globals);
            android.content.SharedPreferences.Editor edit=prefs.edit().clear();
            for(java.util.Map.Entry<String,?> e:previous.entrySet()) {
                Object v=e.getValue();
                if(v instanceof String)edit.putString(e.getKey(),(String)v);
                else if(v instanceof Boolean)edit.putBoolean(e.getKey(),(Boolean)v);
                else if(v instanceof Long)edit.putLong(e.getKey(),(Long)v);
                else if(v instanceof Integer)edit.putInt(e.getKey(),(Integer)v);
                else if(v instanceof Float)edit.putFloat(e.getKey(),(Float)v);
            }
            edit.putString("state","off").putBoolean("desired",false).apply();
        }
    }
    private void userRulesChecks(Context target,Bundle report) throws Exception {
        String normalized=UserRules.parse(" HTTPS://Example.COM:443/path?q=1\r\n*.example.com\nпример.рф\n api.example.net. ");
        if(!normalized.equals("example.com\nxn--e1afmkfd.xn--p1ai\napi.example.net"))throw new AssertionError(normalized);
        for(String bad:new String[]{"file:///x","https://user:password@example.com","localhost","127.0.0.1","example..com","https://example.com:0","example.com & calc.exe"}) {
            try {UserRules.parse(bad);throw new AssertionError("Accepted invalid domain: "+bad);}catch(IllegalArgumentException expected) { }
        }
        android.content.SharedPreferences prefs=Settings.prefs(target);
        java.util.Map<String,?> previous=new java.util.HashMap<>(prefs.getAll());
        String oldGeo=UserRules.text(target,"geo_domains");
        prefs.edit().putBoolean("auto_updates",false).putBoolean("ai_relay",false).putBoolean("telegram_relay",false)
            .putLong("apk_update_checked",System.currentTimeMillis()).apply();
        MainActivity activity=(MainActivity)startActivitySync(new Intent(target,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        try {
            java.util.concurrent.atomic.AtomicReference<android.app.AlertDialog> dialogRef=new java.util.concurrent.atomic.AtomicReference<>();
            java.util.concurrent.atomic.AtomicReference<String> formError=new java.util.concurrent.atomic.AtomicReference<>();
            runOnMainSync(()->dialogRef.set(activity.userRules()));waitForIdleSync();
            runOnMainSync(()-> {
                android.app.AlertDialog dialog=dialogRef.get();
                android.widget.EditText geo=dialog.findViewById(UserRules.GEO_FIELD_ID),direct=dialog.findViewById(UserRules.DIRECT_FIELD_ID);
                geo.setText("HTTPS://Example.COM/path\n*.example.com");direct.setText("bad domain");
                dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).performClick();
                if(!dialog.isShowing()||direct.getError()==null||!UserRules.text(target,"geo_domains").equals(oldGeo)) {formError.set("Invalid input changed preferences");return;}
                direct.setText("chatgpt.com");dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).performClick();
                if(dialog.isShowing())formError.set("Valid form remained open");
            });
            if(formError.get()!=null)throw new AssertionError(formError.get());
            if(!UserRules.text(target,"geo_domains").equals("example.com")||!UserRules.text(target,"direct_domains").equals("chatgpt.com"))throw new AssertionError("GUI rules not saved");
            Settings.prefs(target).edit().putBoolean("dpi",false).putBoolean("telegram",false).putBoolean("extra_sites",false).apply();
            if(!Settings.vpn(target))throw new AssertionError("Custom geo-only mode did not request VPN");
            org.json.JSONObject routes=new org.json.JSONObject().put("smart_dns",true).put("own_ip",true).put("telegram_relay",false).put("ai",1084).put("builtin_extras",false)
                .put("geo_domains",UserRules.domains(target,"geo_domains")).put("direct_domains",UserRules.domains(target,"direct_domains"));
            com.chaquo.python.PyObject globals=Python.getInstance().getModule("builtins").callAttr("dict");globals.callAttr("__setitem__","routes",routes.toString());
            Python.getInstance().getModule("builtins").callAttr("exec","import json\nfrom user_rules import DomainRules\nr=json.loads(routes)\np=DomainRules(r['geo_domains'],r['direct_domains'],r['builtin_extras'])\nassert p.is_geo('api.example.com') and not p.is_geo('chatgpt.com') and p.is_direct('api.chatgpt.com')\n",globals);
            DataUpdates.module(target).callAttr("materialize",target.getFilesDir().getPath());
            if(!UserRules.text(target,"geo_domains").equals("example.com"))throw new AssertionError("Materialization overwrote user preferences");
            BridgeService.start(target);waitFor(target,"on",30000);
            if(!Settings.prefs(target).getBoolean("vpn_active",false))throw new AssertionError("Custom-only VPN is not active");
            org.json.JSONObject policy=new org.json.JSONObject(Python.getInstance().getModule("android_bridge").callAttr("diagnostics").toString());
            if(!policy.optBoolean("own_ip") || policy.optBoolean("telegram_external_relays") || policy.has("smart_dns_provider") || policy.getJSONObject("routes").getInt("ai")!=1084)
                throw new AssertionError("Custom rules do not use own-IP route");
            BridgeService.stop(target);waitFor(target,"off",20000);
            report.putString("user_rules","PASS: native editor, invalid input rejection, normalization, preferences, materialization preservation, custom-only VPN lifecycle and Java/Python policy");
        } finally {
            try {BridgeService.stop(target);waitFor(target,"off",20000);}
            finally {restoreCheckPreferences(prefs,previous);runOnMainSync(activity::finish);}
        }
    }
    @android.annotation.SuppressLint("UnspecifiedRegisterReceiverFlag") // Test-only cross-UID callback; exported flags exist from API 33.
    private void dataPath(Context target, Bundle report, String strategy) throws Exception {
        android.content.SharedPreferences prefs=Settings.prefs(target);
        java.util.Map<String,?> previous=new java.util.HashMap<>(prefs.getAll());
        com.chaquo.python.PyObject tlsGlobals=Python.getInstance().getModule("builtins").callAttr("dict");
        boolean localTls=arguments.getString("tlsCa")!=null;
        boolean extrasOnly=strategy.equals("extras-only");
        boolean extraSites=extrasOnly || Boolean.parseBoolean(arguments.getString("extraSites","false"));
        if(localTls)Python.getInstance().getModule("builtins").callAttr("exec",
            "import doh,traffic\n_saved_resolve=doh.Resolver.resolve\n"+
            "async def local_resolve(self,host):\n return '10.0.2.2'\n"+
            "doh.Resolver.resolve=local_resolve\ntraffic.Routes.inspect_ports.add(18890)\n",tlsGlobals);
        boolean discordUnavailable=strategy.equals("discord-unavailable");
        boolean mixed=strategy.equals("mixed") || discordUnavailable;
        if(mixed)clearStrategyMemory(target);
        if(mixed)Python.getInstance().getModule("builtins").callAttr("exec",
            "import strategy_probe,json\n_saved_probe=strategy_probe.probe\n"+
            "def mixed_probe(port,control):\n"+
            " label=control.getSharedPreferences('bridge',0).getString('probe_status','')\n"+
            " youtube=label.endswith(' · TLS')\n candidate=label.endswith(' · ByeDPI / Disorder')\n"+
            " discord=candidate and "+(discordUnavailable?"False":"True")+"\n"+
            " return json.dumps({'passed':int(youtube)+int(discord),'total':2,'complete':False,'dns':{'ok':True,'provider':'test'},'targets':[{'name':'YouTube','ok':youtube},{'name':'Discord','ok':discord,'api_ok':candidate,'gateway_ok':discord,'cdn_ok':candidate}]})\n"+
            "strategy_probe.probe=mixed_probe\n",tlsGlobals);
        java.util.concurrent.CountDownLatch ready = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicReference<String> result = new java.util.concurrent.atomic.AtomicReference<>();
        BroadcastReceiver receiver=new BroadcastReceiver() {
            @Override public void onReceive(Context c,Intent intent) { result.set(intent.getStringExtra("result")); ready.countDown(); }
        };
        IntentFilter filter=new IntentFilter("dev.graybridge.probe.RESULT");
        if(android.os.Build.VERSION.SDK_INT>=33) target.registerReceiver(receiver,filter,Context.RECEIVER_EXPORTED);
        else target.registerReceiver(receiver,filter);
        try {
            Settings.prefs(target).edit().putString("strategy",mixed || extrasOnly?"auto":strategy).putBoolean("dpi",!extrasOnly)
                .putBoolean("telegram",!extrasOnly).putBoolean("extra_sites",extraSites).putBoolean("auto_updates",false)
                .putBoolean("ai_relay",false).putBoolean("telegram_relay",false).apply();
            target.startActivity(new Intent(target,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            BridgeService.start(target); waitForEngine(target,30000);
            if(mixed && !Settings.prefs(target).getString("active_strategy","").contains("Discord: ByeDPI / Disorder"))
                throw new AssertionError("Independent service methods were not selected");
            if(discordUnavailable && !Settings.prefs(target).getString("probe_result","").contains("не все пройдены"))
                throw new AssertionError("Failed Discord gateway was incorrectly reported as successful");
            if(localTls && !extrasOnly) {
                tlsGlobals.callAttr("__setitem__","_test_ca",arguments.getString("tlsCa"));
                tlsGlobals.callAttr("__setitem__","_discord_port",mixed?1083:1080);
                Python.getInstance().getModule("builtins").callAttr("exec",
                    "import asyncio,ssl,base64,discord_gateway\n"+
                    "context=ssl.create_default_context()\n"+
                    "context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(base64.b64decode(_test_ca)))\n"+
                    "detail=asyncio.run(discord_gateway.check_gateway(_discord_port,'10.0.2.2',context,10,18890))\n"+
                    "assert detail['ok'],detail\n",tlsGlobals);
                report.putString("gateway","PASS: certificate-verified Python SOCKS/TLS/WebSocket Hello");
            }
            target.startActivity(new Intent().setComponent(new ComponentName("dev.graybridge.probe","dev.graybridge.probe.ProbeActivity"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TASK).putExtra("requireVpn",true)
                .putExtra("callbackPackage",target.getPackageName())
                .putExtra("tlsCa",arguments.getString("tlsCa")).putExtra("extraSites",extraSites));
            if(!ready.await(45,java.util.concurrent.TimeUnit.SECONDS)) throw new AssertionError("No separate UID probe response");
            if(result.get()==null || !result.get().startsWith("PASS:")) throw new AssertionError(result.get());
            report.putString("datapath",strategy+": "+result.get());
            long[] stats=NativeTunnel.stats();
            if(stats[1]<128*1024 || stats[3]<128*1024) throw new AssertionError("TUN byte counters do not confirm probe transfer");
            report.putString("tunnel","PASS: tx_bytes="+stats[1]+", rx_bytes="+stats[3]);
            if(localTls) {
                org.json.JSONObject traffic=new org.json.JSONObject(Python.getInstance().getModule("android_bridge").callAttr("diagnostics").toString());
                if(!traffic.optBoolean("own_ip") || traffic.optBoolean("telegram_external_relays") || traffic.has("smart_dns_provider") || traffic.optInt("geo_attempts")!=0)
                    throw new AssertionError("Own-IP service traffic used a relay");
                if(traffic.optInt("direct_tcp")<1 || (!extrasOnly && (traffic.optInt("youtube_tcp")<1 || traffic.optInt("discord_tcp")<1)))
                    throw new AssertionError("HTTPS service routing counters incomplete: "+traffic);
                if(extraSites && (traffic.optInt("ai_tcp")<3 || traffic.optInt("instagram_tcp")<2 || traffic.getJSONObject("routes").getInt("instagram")!=1084))
                    throw new AssertionError("Extra service routing counters incomplete: "+traffic);
                if(extrasOnly && (traffic.optInt("youtube_tcp")!=0 || traffic.optInt("discord_tcp")!=0))
                    throw new AssertionError("Disabled DPI routes were active: "+traffic);
                report.putString("routing",traffic.toString());
                if(mixed && traffic.getJSONObject("routes").getInt("discord")!=1083)
                    throw new AssertionError("Discord was not routed to its separate native process");
            }
        } finally {
            try {
            target.unregisterReceiver(receiver);
            BridgeService.stop(target); waitFor(target,"off",20000);
            if(localTls)Python.getInstance().getModule("builtins").callAttr("exec",
                "doh.Resolver.resolve=_saved_resolve\ntraffic.Routes.inspect_ports.discard(18890)\n",tlsGlobals);
            if(mixed)clearStrategyMemory(target);
        if(mixed)Python.getInstance().getModule("builtins").callAttr("exec",
                "strategy_probe.probe=_saved_probe\n",tlsGlobals);
            for(int port:new int[]{1080,1081,1082,1083,1084,1443}) {
                try(java.net.Socket socket=new java.net.Socket("127.0.0.1",port)) {
                    throw new AssertionError("Port remained open after dataPath test: "+port);
                } catch(java.io.IOException expected) { }
            }
            } finally {restoreCheckPreferences(prefs,previous);}
        }
    }
    private void telegramDpiChecks(Context target,Bundle report,String certificate) throws Exception {
        android.content.SharedPreferences prefs=Settings.prefs(target);
        java.util.Map<String,?> previous=new java.util.HashMap<>(prefs.getAll());
        try {
            prefs.edit().putBoolean("dpi",false).putBoolean("telegram",true).putBoolean("extra_sites",false)
                .putBoolean("ai_relay",false).putBoolean("telegram_relay",false)
                .putBoolean("auto_updates",false).putString("geo_domains","").putString("direct_domains","").apply();
            BridgeService.start(target);waitFor(target,"on",30000);
            com.chaquo.python.PyObject globals=Python.getInstance().getModule("builtins").callAttr("dict");
            Python.getInstance().getModule("builtins").callAttr("exec",
                "from proxy.config import proxy_config\nfrom proxy import tg_ws_proxy\nassert not proxy_config.fallback_cfproxy and not proxy_config.cfproxy_worker_domains\nassert tg_ws_proxy.cf_h2_pool is None and proxy_config.telegram_dpi_port==1084\n",globals);
            try(java.io.InputStream input=getContext().getAssets().open("telegram_dpi_check.py")) {
                Python.getInstance().getModule("builtins").callAttr("exec",readUtf8(input),globals);
            }
            String pem;
            try(java.io.InputStream input=new java.io.FileInputStream(certificate)){pem=readUtf8(input);}
            com.chaquo.python.PyObject result=Python.getInstance().getModule("asyncio").callAttr("run",
                globals.callAttr("__getitem__","run").call(1084,pem));
            report.putString("telegram_dpi",Python.getInstance().getModule("json").callAttr("dumps",result).toString());
            if(!Python.getInstance().getModule("android_bridge").callAttr("is_running").toBoolean())
                throw new AssertionError("Telegram engine stopped during WSS transfer");
        } finally {
            BridgeService.stop(target);waitFor(target,"off",20000);
            android.content.SharedPreferences.Editor editor=prefs.edit().clear();
            for(java.util.Map.Entry<String,?> entry:previous.entrySet()) {
                Object value=entry.getValue();String key=entry.getKey();
                if(value instanceof String)editor.putString(key,(String)value);
                else if(value instanceof Boolean)editor.putBoolean(key,(Boolean)value);
                else if(value instanceof Integer)editor.putInt(key,(Integer)value);
                else if(value instanceof Long)editor.putLong(key,(Long)value);
                else if(value instanceof Float)editor.putFloat(key,(Float)value);
            }
            editor.apply();
        }
    }
    private static String readUtf8(java.io.InputStream input) throws java.io.IOException {
        java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();byte[] b=new byte[4096];int n;
        while((n=input.read(b))!=-1)out.write(b,0,n);return out.toString("UTF-8");
    }
    private void waitFor(Context target,String expected,long timeout) throws InterruptedException {
        long end=System.currentTimeMillis()+timeout;
        while(System.currentTimeMillis()<end) {
            String value=Settings.state(target);
            if(value.equals(expected)) return;
            if(value.equals("error")) throw new AssertionError(Settings.prefs(target).getString("error","unknown"));
            Thread.sleep(100);
        }
        StringBuilder stacks=new StringBuilder();
        for(java.util.Map.Entry<Thread,StackTraceElement[]> e:Thread.getAllStackTraces().entrySet()) {
            if(e.getKey().getName().startsWith("pool-")||e.getKey().getName().equals("graybridge-network")) {
                stacks.append("\n").append(e.getKey().getName());
                for(StackTraceElement f:e.getValue())stacks.append("\n ").append(f.toString());
            }
        }
        throw new AssertionError("Timed out waiting for "+expected+", got "+Settings.state(target)+stacks);
    }
}
