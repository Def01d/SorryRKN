package dev.graybridge;

import android.content.Context;
import android.util.Base64;
import com.jcraft.jsch.*;
import org.json.JSONObject;
import java.io.*;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

final class ServerSSH {
    static final class Untrusted extends Exception {
        final String fingerprint;
        Untrusted(String value){ fingerprint=value; }
    }
    static String host(String input) throws IOException {
        String value=input.trim();
        if(value.startsWith("[") && value.endsWith("]")) value=value.substring(1,value.length()-1);
        if(value.matches("[a-zA-Z0-9](?:[A-Za-z0-9.-]{0,251}[a-zA-Z0-9])?") && !value.contains("..")) return value;
        if (value.matches("[0-9a-fA-F:]+") && InetAddress.getByName(value) instanceof Inet6Address) return value;
        throw new IOException("Некорректный адрес сервера");
    }
    static String run(Context c, JSONObject server, String password, String action) throws Exception {
        return run(c,server,password,action,null);
    }
    static String run(Context c, JSONObject server, String password, String action,byte[] identity) throws Exception {
        boolean reality=action.startsWith("reality-");
        if (!java.util.Arrays.asList("https-on","https-profile","https-start","https-off","https-status","install-socks","stop-socks","reality-on","reality-off","reality-profile","reality-status").contains(action)) throw new IOException();
        String host=host(server.getString("host")), user=server.getString("user");
        int port=server.getInt("port");
        if(port<1 || port>65535 || !user.matches("[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}")) throw new IOException();
        String id=server.optString("device", "");
        if(id.isEmpty()) {
            id=Settings.prefs(c).getString("remote_device_id","");
            if(id.isEmpty()) {id=UUID.randomUUID().toString().replace("-","");if(!Settings.prefs(c).edit().putString("remote_device_id",id).commit())throw new IOException();}
            server.put("device",id);
        }
        if(!id.matches("[0-9a-f]{32}")) throw new IOException();
        String pinned=server.optString("pin","");
        String[] offered=new String[1];
        JSch jsch=new JSch();
        if(identity!=null)jsch.addIdentity("selected",identity.clone(),null,password.isEmpty()?null:password.getBytes(StandardCharsets.UTF_8));
        jsch.setHostKeyRepository(new HostKeyRepository() {
            public int check(String name,byte[] key) {
                try { offered[0]="SHA256:"+Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(key),Base64.NO_PADDING|Base64.NO_WRAP); }
                catch(Exception e){return CHANGED;}
                return pinned.isEmpty()?NOT_INCLUDED:pinned.equals(offered[0])?OK:CHANGED;
            }
            public void add(HostKey key,UserInfo ui) {}
            public void remove(String host,String type) {}
            public void remove(String host,String type,byte[] key) {}
            public String getKnownHostsRepositoryID(){return "SorryRKN";}
            public HostKey[] getHostKey(){return new HostKey[0];}
            public HostKey[] getHostKey(String host,String type){return new HostKey[0];}
        });
        Session session=jsch.getSession(user,host,port);
        session.setConfig("StrictHostKeyChecking","yes");
        session.setConfig("PreferredAuthentications",identity==null?"password":"publickey");
        if(identity==null)session.setPassword(password);
        session.setTimeout(15000);
        boolean forwarded=false;
        try {
            try { session.connect(15000); } catch(JSchException e) {
                if(offered[0]!=null && pinned.isEmpty()) throw new Untrusted(offered[0]);
                if(offered[0]!=null && !pinned.equals(offered[0])) throw new IOException("Ключ сервера изменился. Подключение отклонено.");
                throw new IOException("Не удалось подключиться по SSH. Проверьте сеть, логин и пароль.");
            }
            session.setServerAliveInterval(10000);
            ChannelExec exec=(ChannelExec)session.openChannel("exec");
            try(InputStream script=c.getAssets().open(reality?"reality.sh":"provision.sh")) {
                exec.setCommand(("root".equals(user)?"":"sudo -n ")+"sh -s -- "+action+" "+id+(reality?"":" "+host));
                exec.setInputStream(script);
                exec.setErrStream(new OutputStream(){public void write(int b){} public void write(byte[] b,int o,int n){}});
                InputStream output=exec.getInputStream(); exec.connect(15000);
                long end=android.os.SystemClock.elapsedRealtime()+300000;
                ByteArrayOutputStream response=new ByteArrayOutputStream();
                byte[] buf=new byte[4096];
                while(android.os.SystemClock.elapsedRealtime()<end) {
                    while(output.available()>0) {
                        int n=output.read(buf,0,Math.min(buf.length,output.available()));
                        if(n<=0) break;
                        if(response.size()+n>65536) throw new IOException("Слишком большой ответ сервера");
                        response.write(buf,0,n);
                    }
                    if(exec.isClosed() && output.available()==0) break;
                    Thread.sleep(75);
                }
                if(!exec.isClosed() || exec.getExitStatus()!=0) throw new IOException("Сервер отклонил операцию. Требуется поддерживаемый Linux и root или sudo без пароля.");
                String text=response.toString("UTF-8").trim();
                int newline=text.lastIndexOf('\n');
                String result=text.substring(newline+1);
                if("install-socks".equals(action) && result.startsWith("SRKN1\tSOCKS\t127.0.0.1\t11080\t")) {
                    int local=session.setPortForwardingL("127.0.0.1",0,"127.0.0.1",11080);
                    SshForward.keep(c,session,local);
                    forwarded=true;
                }
                if("stop-socks".equals(action))SshForward.stop(c);
                return result;
            } finally { exec.disconnect(); }
        } finally { if(!forwarded)session.disconnect(); }
    }
    static String apply(JSONObject server,String record) throws Exception {
        String[] v=record.split("\\t",-1);
        if(v.length<2 || !"SRKN1".equals(v[0])) throw new IOException("Неизвестный ответ сервера");
        if("REALITY".equals(v[1]) && v.length==3) {
            java.net.URI uri=new java.net.URI(v[2]);
            if(!"vless".equals(uri.getScheme()) || !"sorryrkn.invalid".equals(uri.getHost()) || uri.getPort()!=8443 || uri.getRawUserInfo()==null)
                throw new IOException("Некорректный профиль REALITY");
            java.util.UUID.fromString(uri.getRawUserInfo());
            String remote=host(server.getString("host")); if(remote.contains(":"))remote="["+remote+"]";
            server.put("reality",v[2].replace("@sorryrkn.invalid:8443","@"+remote+":8443"));
            return "Узел сервера добавлен в Подписки.";
        }
        if("REALITY-STATUS".equals(v[1]) && v.length==3 && v[2].matches("running|stopped|missing")) return "REALITY · "+v[2];
        if ("HTTPS".equals(v[1]) && v.length==3) {
            server.put("https",NaiveEngine.provisioned(v[2],server.getString("host")));
            return "Профиль HTTPS сохранён";
        }
        if("SOCKS".equals(v[1]) && v.length==6) {
            if(!v[2].matches("[0-9.]{7,15}") || !v[3].matches("[0-9]{1,5}") || !v[4].matches("[A-Za-z0-9._-]{1,80}") || !v[5].matches("[A-Za-z0-9+/=_-]{1,128}")) throw new IOException();
            server.put("socks",v[4]+"\n"+v[5]);
            return "SOCKS5 готов на устройстве через защищённый SSH-канал.";
        }
        if("STATUS".equals(v[1]) && v.length==4 && v[2].matches("vpn:(running|stopped|missing)") && v[3].matches("socks:(running|stopped|missing)")) return v[2]+" · "+v[3];
        throw new IOException("Неожиданный ответ сервера");
    }
}
