package dev.graybridge;

import android.content.Context;
import android.net.Uri;
import android.util.Base64;
import java.net.*;
import java.io.*;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.net.ssl.*;

/** A different CA on the same SSH-verified private HTTPS endpoint must break the TLS exchange. */
final class NegativeTrustProbe {
    static void run(Context c,String good) throws Exception {
        Uri original=Uri.parse(good);
        if(original.getQueryParameter("ca")==null)throw new AssertionError("Requires private CA test fixture");
        KeyStore system=KeyStore.getInstance("AndroidCAStore");system.load(null);
        Enumeration<String> aliases=system.aliases();
        X509Certificate alternate=null;
        while(aliases.hasMoreElements()) {
            X509Certificate candidate=(X509Certificate)system.getCertificate(aliases.nextElement());
            try {candidate.checkValidity();alternate=candidate;break;}catch(java.security.cert.CertificateException expired){}
        }
        if(alternate==null)throw new AssertionError("No alternate CA");
        String ca=Base64.encodeToString(alternate.getEncoded(),Base64.URL_SAFE|Base64.NO_PADDING|Base64.NO_WRAP);
        String bad=original.buildUpon().clearQuery().appendQueryParameter("sni",original.getQueryParameter("sni")).appendQueryParameter("ca",ca).build().toString();
        NaiveEngine naive=new NaiveEngine();
        int port;try(ServerSocket reserve=new ServerSocket(0,1,InetAddress.getLoopbackAddress())){port=reserve.getLocalPort();}
        java.lang.Process child=naive.start(c,bad,port,"fixture");
        try {
            Socket socket=null;
            for(int i=0;i<50&&child.isAlive();i++){
                try{socket=new Socket("127.0.0.1",port);break;}catch(IOException ignored){Thread.sleep(100);}
            }
            if(socket==null)throw new AssertionError("Negative fixture listener did not start");
            try(Socket local=socket){
                local.setSoTimeout(12000);
                DataInputStream in=new DataInputStream(local.getInputStream());OutputStream out=local.getOutputStream();
                out.write(new byte[]{5,1,2});if(in.read()!=5||in.read()!=2)throw new AssertionError("Listener method");
                out.write(new byte[]{1,5,'l','o','c','a','l',7,'f','i','x','t','u','r','e'});
                if(in.read()!=1||in.read()!=0)throw new AssertionError("Listener authentication");
                String domain="www.gstatic.com";byte[] host=domain.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                try {
                    out.write(new byte[]{5,1,0,3,(byte)host.length});out.write(host);out.write(new byte[]{1,(byte)187});
                    if(in.read()!=5||in.read()!=0)return;
                    in.read();int type=in.read();
                    int length=type==1?4:type==4?16:in.readUnsignedByte();
                    in.readFully(new byte[length+2]);
                    try(SSLSocket tls=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(local,domain,443,true)){
                        tls.setSoTimeout(12000);tls.startHandshake();
                    }
                }catch(IOException rejected){return;}
                throw new AssertionError("HTTPS proxy accepted a different CA");
            }
        } finally{child.destroyForcibly();naive.close();}
    }
}
