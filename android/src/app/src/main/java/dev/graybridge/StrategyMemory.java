package dev.graybridge;

import android.content.Context;
import org.json.*;
import java.util.List;

/** Local per-network choices. Unrelated list/TG updates do not invalidate them. */
final class StrategyMemory {
    static final class Choice {
        final Strategies.Profile youtube, discord;
        final int discordQuality;
        Choice(Strategies.Profile youtube, Strategies.Profile discord, int quality) {
            this.youtube=youtube;this.discord=discord;this.discordQuality=quality;
        }
    }
    private static String signature(Strategies.Profile p) {
        return p.engine + ":" + new JSONArray(p.args).toString();
    }
    private static Strategies.Profile find(List<Strategies.Profile> profiles,String id) {
        for(Strategies.Profile p:profiles) if(p.id.equals(id))return p;
        return null;
    }
    static Choice load(Context c,String key,List<Strategies.Profile> profiles) {
        try {
            String value=Settings.prefs(c).getString(key+"_memory","");
            if(value.isEmpty()) {
                // Migrate existing successful choices, then verify in the background.
                Strategies.Profile youtube=find(profiles,Settings.prefs(c).getString(key,""));
                Strategies.Profile discord=find(profiles,Settings.prefs(c).getString(key+"_discord",""));
                return youtube==null?null:new Choice(youtube,discord==null?youtube:discord,discord==null?4:6);
            }
            JSONObject saved=new JSONObject(value);
            Strategies.Profile youtube=find(profiles,saved.optString("youtube"));
            Strategies.Profile discord=find(profiles,saved.optString("discord"));
            if(youtube==null||discord==null||!signature(youtube).equals(saved.optString("youtube_args"))||
               !signature(discord).equals(saved.optString("discord_args")))return null;
            return new Choice(youtube,discord,saved.optInt("discord_quality",6));
        } catch(JSONException e) {return null;}
    }
    static void save(Context c,String key,Strategies.Profile youtube,Strategies.Profile discord,int quality) {
        if(youtube==null||discord==null)return;
        try {
            JSONObject saved=new JSONObject().put("youtube",youtube.id).put("discord",discord.id)
                .put("youtube_args",signature(youtube)).put("discord_args",signature(discord))
                .put("discord_quality",quality);
            Settings.prefs(c).edit().putString(key+"_memory",saved.toString()).apply();
        } catch(JSONException ignored) { }
    }
    static int quality(JSONObject result) {
        JSONArray targets=result.optJSONArray("targets");
        if(targets!=null)for(int i=0;i<targets.length();i++) {
            JSONObject target=targets.optJSONObject(i);
            if(target!=null && target.optString("name").equals("Discord"))
                return (target.optBoolean("api_ok")?1:0)+(target.optBoolean("gateway_ok")?4:0)+(target.optBoolean("cdn_ok")?1:0);
        }
        return 0;
    }
    static boolean youtubeOK(JSONObject result) {
        JSONArray targets=result.optJSONArray("targets");
        if(targets!=null)for(int i=0;i<targets.length();i++) {
            JSONObject target=targets.optJSONObject(i);
            if(target!=null && target.optString("name").equals("YouTube"))return target.optBoolean("ok");
        }
        return false;
    }
}
