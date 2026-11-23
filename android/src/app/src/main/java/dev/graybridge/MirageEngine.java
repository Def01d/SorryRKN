package dev.graybridge;

import android.content.Context;
import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/** Runs the SRKN-Mirage Go client binary with config credentials passed via temporary mode-0600 file. */
final class MirageEngine {
    private File cfg;

    java.lang.Process start(Context c, String uri, int port, String password) throws Exception {
        if (uri == null || !uri.startsWith("mirage://")) {
            throw new IOException("Некорректный профиль Мираж");
        }
        JSONObject config = new JSONObject()
            .put("uri", uri)
            .put("listen", "127.0.0.1:" + port)
            .put("socks_user", "local")
            .put("socks_pass", password);
        cfg = File.createTempFile("mirage-", ".json", c.getCacheDir());
        Files.write(cfg.toPath(), config.toString().getBytes(StandardCharsets.UTF_8));
        File exe = new File(c.getApplicationInfo().nativeLibraryDir, "libmirage.so");
        ProcessBuilder proc = new ProcessBuilder(exe.toString(), "client", "--config", cfg.toString())
            .redirectOutput(new File("/dev/null"))
            .redirectError(new File("/dev/null"));
        if (BuildConfig.DEBUG) {
            proc.redirectErrorStream(true).redirectOutput(new File(c.getCacheDir(), "mirage-engine-test.log"));
        }
        return proc.start();
    }

    void ready() {
        if (cfg != null) {
            cfg.delete();
        }
    }

    void close() {
        ready();
    }
}
