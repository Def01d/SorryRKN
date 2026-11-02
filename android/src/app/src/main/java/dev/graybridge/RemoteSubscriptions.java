package dev.graybridge;

import android.content.Context;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;
import org.json.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

final class RemoteSubscriptions {
    static JSONObject library(Context c) throws Exception {
        JSONObject book=RemoteVault.read(c,"subscriptions");
        if(!book.has("groups")) book.put("groups",new JSONArray());
        return book;
    }
    static JSONObject selected(JSONObject book) throws Exception {
        return book.getJSONArray("groups").getJSONObject(book.optInt("selected",0));
    }
    static JSONObject outbound(Context c) throws Exception {
        JSONObject group=selected(library(c));
        return group.getJSONArray("nodes").getJSONObject(group.optInt("index",0)).getJSONObject("outbound");
    }
    static String update(Context c,String input,boolean refresh) throws Exception {
        JSONObject book=library(c);
        JSONArray groups=book.getJSONArray("groups");
        int slot=refresh?book.getInt("selected"):groups.length();
        if(slot>=12) throw new IOException("Можно сохранить до 12 подписок");
        String source=input.trim(), body=source;
        boolean url=source.startsWith("https://");
        if(url) {
            if(source.length()>8192) throw new IOException("Слишком длинная ссылка");
            for(int i=0; i<groups.length(); i++) if(source.equals(groups.getJSONObject(i).optString("url"))) { slot=i;break; }
            body=fetch(source);
        }
        if(!Python.isStarted()) Python.start(new AndroidPlatform(c));
        JSONObject group=new JSONObject(Python.getInstance().getModule("remote_nodes").callAttr("parse_subscription",body).toString());
        JSONArray nodes=group.getJSONArray("nodes");
        if(!url && !refresh) {
            String outbound=nodes.getJSONObject(0).getJSONObject("outbound").toString();
            for(int i=0;i<groups.length();i++) {
                JSONObject old=groups.getJSONObject(i);
                if(old.optString("url").isEmpty() && old.getJSONArray("nodes").length()==nodes.length() &&
                    outbound.equals(old.getJSONArray("nodes").getJSONObject(0).getJSONObject("outbound").toString())) {slot=i; break;}
            }
        }
        int index=0;
        if(slot<groups.length()) {
            JSONObject prior=groups.getJSONObject(slot);
            String old=prior.getJSONArray("nodes").getJSONObject(prior.optInt("index",0)).optString("name");
            for(int i=0; i<nodes.length(); i++) if(old.equals(nodes.getJSONObject(i).getString("name"))) { index=i;break; }
        }
        group.put("index",index).put("url",url?source:"")
            .put("name",url?new URL(source).getHost():nodes.getJSONObject(0).getString("name"));
        groups.put(slot,group); book.put("selected",slot);
        if(book.toString().length()>2*1024*1024) throw new IOException("Библиотека заполнена");
        RemoteVault.write(c,"subscriptions",book);
        return "Узлы: "+nodes.length()+" · пропущено: "+group.optInt("skipped",0);
    }
    private static String fetch(String src) throws Exception {
        URL url=new URL(src);
        for(int n=0; n<5; n++) {
            if(!url.getProtocol().equals("https") || url.getHost().isEmpty() || url.getUserInfo()!=null) throw new IOException("Требуется HTTPS");
            HttpURLConnection conn=(HttpURLConnection)url.openConnection();
            try {
                conn.setConnectTimeout(10000); conn.setReadTimeout(12000); conn.setUseCaches(false); conn.setInstanceFollowRedirects(false);
                conn.setRequestProperty("User-Agent","SorryRKN/"+BuildConfig.VERSION_NAME);
                int code=conn.getResponseCode();
                if(code==301||code==302||code==303||code==307||code==308) {
                    String location=conn.getHeaderField("Location");
                    if(location==null) throw new IOException();
                    url=new URL(url,location);continue;
                }
                if(code!=200) throw new IOException("HTTP "+code);
                try(InputStream in=conn.getInputStream(); ByteArrayOutputStream buf=new ByteArrayOutputStream()){
                    byte[] bytes=new byte[8192];int count;
                    long deadline=android.os.SystemClock.elapsedRealtime()+30000;
                    while((count=in.read(bytes))!=-1) {
                        if(buf.size()+count>1024*1024 || android.os.SystemClock.elapsedRealtime()>deadline) throw new IOException("Превышен лимит подписки");
                        buf.write(bytes,0,count);
                    }
                    return buf.toString(StandardCharsets.UTF_8.name());
                }
            } finally { conn.disconnect(); }
        }
        throw new IOException("Слишком много перенаправлений");
    }
}
