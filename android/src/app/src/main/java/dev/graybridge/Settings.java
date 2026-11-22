package dev.graybridge;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import java.security.SecureRandom;

final class Settings {
    private static final int LEGACY_TELEGRAM_PORT = 1443;
    private static final int TELEGRAM_PORT = 31443;
    static SharedPreferences prefs(Context c) { return c.getSharedPreferences("bridge", Context.MODE_PRIVATE); }
    static String state(Context c) { return prefs(c).getString("state", "off"); }
    static boolean busy(Context c) { return !state(c).equals("off") && !state(c).equals("error"); }
    static boolean dpi(Context c) { return prefs(c).getBoolean("dpi", true); }
    static boolean telegram(Context c) { return prefs(c).getBoolean("telegram", true); }
    static boolean extras(Context c) { return prefs(c).getBoolean("extra_sites", true); }
    static boolean instagram(Context c) {
        SharedPreferences p = prefs(c);
        return p.contains("instagram") ? p.getBoolean("instagram", true) : extras(c);
    }
    static boolean aiRelay(Context c) { return prefs(c).getBoolean("ai_relay", true); }
    static boolean telegramRelay(Context c) { return prefs(c).getBoolean("telegram_relay", true); }
    static boolean vpn(Context c) { return dpi(c) || extras(c) || instagram(c) || UserRules.geo(c) || UserRules.dpi(c); }
    static synchronized String secret(Context c) {
        SharedPreferences p = prefs(c);
        String value = p.getString("secret", null);
        if (value == null) {
            byte[] random = new byte[16]; new SecureRandom().nextBytes(random);
            StringBuilder hex = new StringBuilder();
            for (byte b : random) hex.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
            value = hex.toString(); p.edit().putString("secret", value).apply();
        }
        return value;
    }
    static int telegramPort(Context c) { return prefs(c).getInt("telegram_port", TELEGRAM_PORT); }
    static int prepareTelegramPort(Context c) {
        SharedPreferences p = prefs(c);
        int port = p.getInt("telegram_port", p.contains("secret") ? LEGACY_TELEGRAM_PORT : TELEGRAM_PORT);
        if (port == LEGACY_TELEGRAM_PORT) {
            try {
                c.getPackageManager().getPackageInfo("dev.graybridge", 0);
                port = TELEGRAM_PORT;
            } catch (PackageManager.NameNotFoundException ignored) { }
        }
        p.edit().putInt("telegram_port", port).apply();
        return port;
    }
    static String link(Context c) {
        return "tg://proxy?server=127.0.0.1&port=" + telegramPort(c) + "&secret=dd" + secret(c);
    }
}
