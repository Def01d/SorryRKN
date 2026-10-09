package dev.graybridge;

import android.content.Context;
import java.net.IDN;
import java.net.URI;
import java.util.LinkedHashSet;
import org.json.JSONArray;

/** User lists remain in preferences, separate from downloaded profiles. */
final class UserRules {
    static final int MAX_TEXT=32768, MAX_DOMAINS=256;
    static final int GEO_FIELD_ID=1001,DIRECT_FIELD_ID=1002;
    static String parse(String text) {
        if(text.length()>MAX_TEXT) throw new IllegalArgumentException("Список слишком длинный");
        LinkedHashSet<String> hosts=new LinkedHashSet<>();
        for(String raw:text.split("\\r?\\n")) {
            String value=raw.trim(); if(value.isEmpty())continue;
            if(value.startsWith("*."))value=value.substring(2);
            try {
                if(value.matches(".*\\s.*") || value.contains("\\"))throw new Exception();
                URI u=new URI(value.contains("://")?value:"//"+value);
                if(u.getScheme()!=null && !u.getScheme().equalsIgnoreCase("http") && !u.getScheme().equalsIgnoreCase("https"))throw new Exception();
                if(u.getRawUserInfo()!=null || u.getRawAuthority()==null)throw new Exception();
                String authority=u.getRawAuthority();
                if(authority.contains("@") || authority.startsWith("["))throw new Exception();
                int colon=authority.lastIndexOf(':');
                if(colon>=0) {int port=Integer.parseInt(authority.substring(colon+1));if(port<1 || port>65535)throw new Exception();authority=authority.substring(0,colon);}
                String host=IDN.toASCII(authority.endsWith(".")?authority.substring(0,authority.length()-1):authority,IDN.USE_STD3_ASCII_RULES).toLowerCase(java.util.Locale.ROOT);
                if(host.length()>253 || !host.contains(".") || host.matches("[0-9.]+"))throw new Exception();
                for(String label:host.split("\\.",-1))if(!label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"))throw new Exception();
                hosts.add(host);
            } catch(Exception e) {throw new IllegalArgumentException("Неверный домен: "+(value.length()>80?value.substring(0,80):value));}
            if(hosts.size()>MAX_DOMAINS)throw new IllegalArgumentException("Не больше 256 доменов в каждом списке");
        }
        String normalized=String.join("\n",hosts);
        if(normalized.length()>MAX_TEXT)throw new IllegalArgumentException("Список доменов после преобразования слишком длинный");
        return normalized;
    }
    static String text(Context c,String key) {return Settings.prefs(c).getString(key,"");}
    static JSONArray domains(Context c,String key) {
        JSONArray array=new JSONArray();String value=parse(text(c,key));
        if(!value.isEmpty())for(String host:value.split("\n"))array.put(host);
        return array;
    }
    static boolean geo(Context c) {return !text(c,"geo_domains").trim().isEmpty();}
}
