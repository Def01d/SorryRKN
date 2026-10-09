package dev.graybridge;

import android.content.Context;
import org.json.*;
import java.util.*;

final class Strategies {
    static final class Profile {
        final String id, name, source, engine;
        final List<String> args = new ArrayList<>();
        Profile(JSONObject json) throws JSONException {
            id = json.getString("id"); name = json.getString("name"); source = json.optString("source", "tpws");
            engine = json.optString("engine", "tpws");
            JSONArray options = json.getJSONArray("args");
            for (int i = 0; i < options.length(); i++) args.add(options.getString(i));
        }
    }
    static List<Profile> load(Context c) throws Exception {
        JSONArray json = new JSONArray(DataUpdates.module(c).callAttr("catalog", c.getFilesDir().getPath()).toString());
        return parse(json);
    }
    static List<Profile> parse(JSONArray json) throws JSONException {
        List<Profile> result = new ArrayList<>();
        for (int i = 0; i < json.length(); i++) result.add(new Profile(json.getJSONObject(i)));
        return result;
    }
    static boolean auto(Context c) { return Settings.prefs(c).getString("strategy", "auto").equals("auto"); }
}
