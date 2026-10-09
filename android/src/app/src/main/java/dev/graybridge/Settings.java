package dev.graybridge;

import android.content.Context;
import android.content.SharedPreferences;
import java.security.SecureRandom;

final class Settings {
    static SharedPreferences prefs(Context c) { return c.getSharedPreferences("bridge", Context.MODE_PRIVATE); }
    static String state(Context c) { return prefs(c).getString("state", "off"); }
    static boolean busy(Context c) { return !state(c).equals("off") && !state(c).equals("error"); }
    static boolean dpi(Context c) { return prefs(c).getBoolean("dpi", true); }
    static boolean telegram(Context c) { return prefs(c).getBoolean("telegram", true); }
    static boolean extras(Context c) { return prefs(c).getBoolean("extra_sites", false); }
    static boolean vpn(Context c) { return dpi(c) || extras(c) || UserRules.geo(c); }
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
    static String link(Context c) { return "tg://proxy?server=127.0.0.1&port=1443&secret=dd" + secret(c); }
}
