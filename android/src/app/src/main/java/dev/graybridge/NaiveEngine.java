package dev.graybridge;

import android.content.Context;
import android.net.Uri;
import android.util.Base64;
import org.json.JSONObject;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/** Only the SSH-provisioned endpoint and its verified trust material enter the Chromium config. */
final class NaiveEngine {
    private File cfg, roots;
    private static URI parse(String profile) throws Exception {
        URI u=new URI(profile);
        if(!"naive+https".equals(u.getScheme()) || u.getRawUserInfo()==null || !u.getRawUserInfo().contains(":") ||
            u.getHost()==null || u.getPort()<1 || u.getPort()>65535 || profile.length()>20000)
            throw new IOException("Некорректный профиль HTTPS");
        return u;
    }
    static String provisioned(String profile,String host) throws Exception {
        URI u=parse(profile);
        if(!"sorryrkn.invalid".equals(u.getHost()) || u.getPort()!=443) throw new IOException("Неожиданный адрес профиля");
        host=ServerSSH.host(host);if(host.contains(":"))host="["+host+"]";
        return profile.replace("@sorryrkn.invalid:443","@"+host+":443");
    }
    static String relay(String profile) throws Exception {
        parse(profile);
        Uri data=Uri.parse(profile);
        if(!data.getQueryParameterNames().contains("relay"))return null;
        java.util.List<String> values=data.getQueryParameters("relay");
        if(values.size()!=1 || !values.get(0).matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
            throw new IOException("Некорректный профиль HTTPS TCP/UDP");
        return values.get(0);
    }
    java.lang.Process start(Context c,String profile,int port,String pass) throws Exception {
        URI u=parse(profile); Uri data=Uri.parse(profile);
        String host=ServerSSH.host(u.getHost());
        String sni=ServerSSH.host(data.getQueryParameter("sni")==null?host:data.getQueryParameter("sni"));
        String tlsAuthority=sni.contains(":")?"["+sni+"]":sni;
        JSONObject config=new JSONObject().put("listen","socks://local:"+pass+"@127.0.0.1:"+port)
            .put("proxy","https://"+u.getRawUserInfo()+"@"+tlsAuthority+":"+u.getPort());
        if(!host.equals(sni)) {
            String ip=InetAddress.getByName(host).getHostAddress();if(ip.contains(":"))ip="["+ip+"]";
            config.put("host-resolver-rules","MAP "+sni+" "+ip);
        }
        cfg=File.createTempFile("https-", ".json", c.getCacheDir());
        Files.write(cfg.toPath(),config.toString().getBytes(StandardCharsets.UTF_8));
        ProcessBuilder proc=new ProcessBuilder(new File(c.getApplicationInfo().nativeLibraryDir,"libnaive.so").toString(),cfg.toString())
            .redirectOutput(new File("/dev/null")).redirectError(new File("/dev/null"));
        String ca=data.getQueryParameter("ca");
        if(ca!=null) {
            byte[] der=Base64.decode(ca,Base64.NO_WRAP|Base64.URL_SAFE);
            if(der.length<1 || der.length>10000)throw new IOException("Некорректный сертификат сервера");
            X509Certificate cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
            cert.checkValidity();
            String pin=data.getQueryParameter("spki");
            if(pin!=null && !MessageDigest.isEqual(Base64.decode(pin,Base64.URL_SAFE|Base64.NO_WRAP),MessageDigest.getInstance("SHA-256").digest(cert.getPublicKey().getEncoded())))
                throw new IOException("Отпечаток сертификата не совпадает");
            roots=File.createTempFile("https-", ".pem", c.getCacheDir());
            String pem="-----BEGIN CERTIFICATE-----\n"+Base64.encodeToString(cert.getEncoded(),Base64.DEFAULT)+"-----END CERTIFICATE-----\n";
            Files.write(roots.toPath(),pem.getBytes(StandardCharsets.US_ASCII));
            proc.environment().put("SSL_CERT_FILE",roots.toString());
            proc.environment().put("SSL_CERT_DIR",new File(c.getCacheDir(),"no-extra-tls-roots").toString());
        } else {
            proc.environment().put("SSL_CERT_DIR","/system/etc/security/cacerts");
        }
        return proc.start();
    }
    void ready(){if(cfg!=null)cfg.delete();}
    void close(){ready();if(roots!=null)roots.delete();}
}
