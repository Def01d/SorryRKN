package dev.graybridge;

import android.app.job.*;
import android.content.*;
import android.os.*;
import com.chaquo.python.*;
import com.chaquo.python.android.AndroidPlatform;
import org.json.*;
import java.io.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Updates declarative GitHub data, never downloaded code or executables. */
public final class DataUpdates {
    private static final int JOB = 204;
    private static final ExecutorService executor = Executors.newSingleThreadExecutor();
    private static final Handler main = new Handler(Looper.getMainLooper());
    private static final AtomicBoolean inFlight = new AtomicBoolean();

    public static class Control {
        private volatile boolean running = true;
        public boolean keepRunning() { return running; }
        public void cancel() { running = false; }
    }

    static synchronized PyObject module(Context context) throws IOException {
        File target = new File(context.getFilesDir(), "bundled-data.json");
        File temporary = new File(context.getFilesDir(), "bundled-data.tmp");
        // Refresh the APK fallback after an app upgrade; retain the GitHub snapshot.
        try (InputStream in = context.getAssets().open("bundled-data.json");
             OutputStream out = new FileOutputStream(temporary)) {
            byte[] buffer = new byte[8192]; int size;
            while ((size = in.read(buffer)) >= 0) out.write(buffer, 0, size);
        }
        if (!temporary.renameTo(target)) throw new IOException("Не удалось сохранить данные APK");
        if (!Python.isStarted()) Python.start(new AndroidPlatform(context.getApplicationContext()));
        return Python.getInstance().getModule("bridge_data");
    }

    static void schedule(Context c) {
        JobScheduler scheduler = c.getSystemService(JobScheduler.class);
        if (!Settings.prefs(c).getBoolean("auto_updates", true)) { scheduler.cancel(JOB); return; }
        if (scheduler.getPendingJob(JOB) != null) return;
        scheduler.schedule(new JobInfo.Builder(JOB, new ComponentName(c, DataUpdateJob.class))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY).setPersisted(true)
            .setPeriodic(24 * 60 * 60 * 1000L, 4 * 60 * 60 * 1000L)
            .setBackoffCriteria(60 * 60 * 1000L, JobInfo.BACKOFF_POLICY_LINEAR).build());
    }

    static void request(Context c, boolean force) {
        Context app = c.getApplicationContext();
        if (!force && !Settings.prefs(app).getBoolean("auto_updates", true)) return;
        if (!force && System.currentTimeMillis() - Settings.prefs(app).getLong("update_attempt", 0) < 3600000) return;
        submit(app, force, new Control(), null);
    }

    static void submit(Context c, boolean force, Control control, java.util.function.Consumer<Boolean> done) {
        if (!inFlight.compareAndSet(false, true)) {
            if (done != null) main.post(() -> done.accept(false));
            return;
        }
        executor.execute(() -> {
            boolean ok;
            try { ok = run(c, force, control); }
            finally { inFlight.set(false); }
            boolean success = ok;
            if (done != null) main.post(() -> done.accept(success));
        });
    }

    private static boolean run(Context c, boolean force, Control control) {
        if (!control.keepRunning()) return false;
        Settings.prefs(c).edit().putLong("update_attempt", System.currentTimeMillis())
            .putString("update_status", "Проверяем GitHub…").apply();
        try {
            PyObject data = module(c);
            JSONObject result = new JSONObject(data.callAttr("update", c.getFilesDir().getPath(), force, null, control).toString());
            if (!control.keepRunning()) return false;
            Settings.prefs(c).edit().putLong("update_checked", result.getLong("checked") * 1000)
                .putString("update_commits", result.getJSONObject("commits").toString())
                .putString("update_status", result.getBoolean("changed")
                    ? "Новые данные сохранены. Стратегии применятся при следующем подборе."
                    : "Данные актуальны").apply();
            // The running Telegram balancer may consume the verified domain pool live.
            Python.getInstance().getModule("android_bridge").callAttr("apply_data", c.getFilesDir().getPath());
            return true;
        } catch (Exception | LinkageError e) {
            if (control.keepRunning()) Settings.prefs(c).edit().putString("update_status",
                "GitHub недоступен или данные несовместимы. Сохранена предыдущая версия.").apply();
            return false;
        }
    }
}
