package dev.graybridge;

import android.app.Application;

public class BridgeApp extends Application {
    @Override public void onCreate() {
        super.onCreate();
        // A persisted UI status never proves the previous process is still running.
        Settings.prefs(this).edit().putString("state", "off").putString("error", "").apply();
        DataUpdates.schedule(this);
    }
}
