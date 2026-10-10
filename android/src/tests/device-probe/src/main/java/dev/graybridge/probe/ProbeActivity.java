package dev.graybridge.probe;
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.net.*;
import android.util.Log;
import android.widget.TextView;
import java.net.*;
import java.io.*;
import java.util.*;
import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;

/** Separate UID so that its sockets are covered by GrayBridge's VPN. */
public class ProbeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView text=new TextView(this); text.setText("Checking VPN TCP / UDP…"); setContentView(text);
        if(getIntent().getBooleanExtra("publicServiceChecks",false)) {
            text.setText("Checking public services through VPN…");
            new Thread(()-> {
                String result,detail;
                try {
                    org.json.JSONObject report=PublicServiceChecks.run(this);
                    detail=report.toString();result=report.getString("result")+": "+report.getInt("passed")+"/"+report.getInt("total")+" public checks";
                } catch(Throwable error) {
                    result="FAIL: "+error.getClass().getSimpleName();detail="{}";
                }
                String callback=getIntent().getStringExtra("callbackPackage");
                if(callback==null)callback="dev.graybridge";
                sendBroadcast(new Intent("dev.graybridge.probe.RESULT").setPackage(callback)
                    .putExtra("result",result).putExtra("publicServices",detail).putExtra("probeToken",getIntent().getStringExtra("probeToken")));
                Log.i("GrayBridgeProbe",result+" "+detail);
                String message=result;runOnUiThread(()->text.setText(message));
            },"public-probe-coordinator").start();
            return;
        }
        new Thread(()-> {
            String result;
            try {
                ConnectivityManager cm=getSystemService(ConnectivityManager.class);
                NetworkCapabilities caps=cm.getNetworkCapabilities(cm.getActiveNetwork());
                long deadline=System.currentTimeMillis()+30000;
                while(getIntent().getBooleanExtra("requireVpn",true) && (caps==null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) && System.currentTimeMillis()<deadline) {
                    Thread.sleep(200); caps=cm.getNetworkCapabilities(cm.getActiveNetwork());
                }
                if(getIntent().getBooleanExtra("requireVpn",true) && (caps==null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))) throw new AssertionError("VPN is not active for the probe UID");
                byte[] payload=new byte[128*1024]; new Random(42).nextBytes(payload);
                try(Socket tcp=new Socket()) {
                    tcp.connect(new InetSocketAddress("10.0.2.2",18888),10000); tcp.setSoTimeout(10000);
                    tcp.getOutputStream().write(payload);
                    ByteArrayOutputStream out=new ByteArrayOutputStream(); byte[] buffer=new byte[8192]; int n;
                    while(out.size()<payload.length && (n=tcp.getInputStream().read(buffer,0,Math.min(buffer.length,payload.length-out.size())))>=0)out.write(buffer,0,n);
                    byte[] response=out.toByteArray();
                    if(response.length!=payload.length)throw new AssertionError("Truncated TCP response: "+response.length);
                    for(int i=0;i<payload.length;i++)if(response[i]!=payload[payload.length-1-i])throw new AssertionError("TCP data mismatch");
                }
                try(DatagramSocket udp=new DatagramSocket()) {
                    udp.setSoTimeout(10000);
                    byte[] sample=Arrays.copyOf(payload,1000);
                    udp.send(new DatagramPacket(sample,sample.length,InetAddress.getByName("10.0.2.2"),18889));
                    DatagramPacket reply=new DatagramPacket(new byte[1500],1500);udp.receive(reply);
                    if(!Arrays.equals(sample,Arrays.copyOf(reply.getData(),reply.getLength())))throw new AssertionError("UDP data mismatch");
                }
                String ca=getIntent().getStringExtra("tlsCa");
                if(getIntent().getBooleanExtra("extraSites",false))checkSmartDnsHints();
                if(ca!=null) checkHttps(ca);
                result="PASS: "+(getIntent().getBooleanExtra("requireVpn",true)?"VPN active":"baseline")+", TCP 128 KiB, UDP 1000 bytes"+(ca!=null?", HTTPS "+(getIntent().getBooleanExtra("extraSites",false)?8:3)+" hosts x 1 MiB, WSS Discord Hello":"")+(getIntent().getBooleanExtra("extraSites",false)?", AI DNS AAAA/HTTPS replies":"");
            } catch(Throwable e) { result="FAIL: "+e; }
            Log.i("GrayBridgeProbe",result);
            String callback=getIntent().getStringExtra("callbackPackage");
            if(callback==null)callback="dev.graybridge";
            sendBroadcast(new Intent("dev.graybridge.probe.RESULT").setPackage(callback).putExtra("result",result));
            String message=result; runOnUiThread(()->text.setText(message));
        },"probe").start();
    }
    private void checkHttps(String encodedCa) throws Exception {
        byte[] der=android.util.Base64.decode(encodedCa,android.util.Base64.DEFAULT);
        KeyStore trust=KeyStore.getInstance(KeyStore.getDefaultType()); trust.load(null,null);
        trust.setCertificateEntry("test-ca",CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der)));
        TrustManagerFactory managers=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());managers.init(trust);
        SSLContext ctx=SSLContext.getInstance("TLS");ctx.init(null,managers.getTrustManagers(),null);
        java.util.List<String> hosts=new java.util.ArrayList<>(Arrays.asList("normal.example.test","www.youtube.com","discord.com"));
        if(getIntent().getBooleanExtra("extraSites",false))hosts.addAll(Arrays.asList("chatgpt.com","claude.ai","gemini.google.com","instagram.com","scontent.cdninstagram.com"));
        for(String host:hosts) {
            Socket raw=new Socket();raw.connect(new InetSocketAddress("10.0.2.2",18890),10000);
            try(SSLSocket tls=(SSLSocket)ctx.getSocketFactory().createSocket(raw,host,18890,true)) {
                tls.setSoTimeout(10000);
                SSLParameters parameters=tls.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");tls.setSSLParameters(parameters);
                tls.startHandshake();
                tls.getOutputStream().write(("GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                InputStream in=tls.getInputStream();
                if(!readHeaders(in).startsWith("HTTP/1.1 200"))throw new AssertionError("HTTPS status: "+host);
                Thread.sleep(500); // Exercise TCP backpressure through the TUN and SOCKS relay.
                byte[] body=new byte[1024*1024];new DataInputStream(in).readFully(body);
                for(int i=0;i<body.length;i++)if((body[i]&255)!=i%251)throw new AssertionError("HTTPS body: "+host);
            }
        }
        String host="gateway.discord.gg";
        Socket raw=new Socket();raw.connect(new InetSocketAddress("10.0.2.2",18890),10000);
        try(SSLSocket tls=(SSLSocket)ctx.getSocketFactory().createSocket(raw,host,18890,true)) {
            tls.setSoTimeout(10000);
            SSLParameters parameters=tls.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");tls.setSSLParameters(parameters);
            tls.startHandshake();
            byte[] nonce=new byte[16];new java.security.SecureRandom().nextBytes(nonce);
            String key=android.util.Base64.encodeToString(nonce,android.util.Base64.NO_WRAP);
            tls.getOutputStream().write(("GET /?v=10&encoding=json HTTP/1.1\r\nHost: "+host+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "+key+"\r\nSec-WebSocket-Version: 13\r\n\r\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            InputStream in=tls.getInputStream();String headers=readHeaders(in);
            String accept=android.util.Base64.encodeToString(java.security.MessageDigest.getInstance("SHA-1").digest(
                (key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(java.nio.charset.StandardCharsets.US_ASCII)),android.util.Base64.NO_WRAP);
            if(!headers.startsWith("HTTP/1.1 101 ") || !headers.contains("Sec-WebSocket-Accept: "+accept+"\r\n"))
                throw new AssertionError("Invalid WSS upgrade");
            DataInputStream data=new DataInputStream(in);
            if(data.readUnsignedByte()!=0x81)throw new AssertionError("Invalid Hello frame");
            int size=data.readUnsignedByte();if(size>125)throw new AssertionError("Unexpected test Hello length");
            byte[] hello=new byte[size];data.readFully(hello);
            org.json.JSONObject message=new org.json.JSONObject(new String(hello,java.nio.charset.StandardCharsets.UTF_8));
            if(message.getInt("op")!=10 || message.getJSONObject("d").getInt("heartbeat_interval")<=0)
                throw new AssertionError("Invalid Discord Hello");
            // Client close is masked, as required by RFC 6455.
            tls.getOutputStream().write(new byte[]{(byte)0x88,(byte)0x82,1,2,3,4,2,(byte)0xea});
        }
    }
    private void checkSmartDnsHints() throws Exception {
        for(int kind:new int[]{28,65}) {
            ByteArrayOutputStream raw=new ByteArrayOutputStream();DataOutputStream query=new DataOutputStream(raw);
            query.writeShort(42);query.writeShort(0x0100);query.writeShort(1);query.writeShort(0);query.writeShort(0);query.writeShort(0);
            for(String label:"gemini.google.com".split("\\.")) {query.writeByte(label.length());query.writeBytes(label);}
            query.writeByte(0);query.writeShort(kind);query.writeShort(1);
            byte[] request=raw.toByteArray();
            try(DatagramSocket socket=new DatagramSocket()) {
                socket.setSoTimeout(10000);
                socket.send(new DatagramPacket(request,request.length,InetAddress.getByName("8.8.8.8"),53));
                DatagramPacket reply=new DatagramPacket(new byte[512],512);socket.receive(reply);
                byte[] data=reply.getData();
                if(reply.getLength()!=request.length || data[0]!=0 || data[1]!=42 || (data[2]&128)==0 || data[6]!=0 || data[7]!=0 || (data[3]&15)!=0)
                    throw new AssertionError("Invalid AI DNS hint response");
                for(int i=12;i<request.length;i++)if(data[i]!=request[i])throw new AssertionError("Altered DNS question");
            }
        }
    }
    private String readHeaders(InputStream in) throws Exception {
        ByteArrayOutputStream headers=new ByteArrayOutputStream();
        while(headers.size()<8192) {
            int value=in.read();if(value<0)throw new EOFException("Short HTTP headers");
            headers.write(value);byte[] h=headers.toByteArray();int n=h.length;
            if(n>=4 && h[n-4]==13 && h[n-3]==10 && h[n-2]==13 && h[n-1]==10)return headers.toString("US-ASCII");
        }
        throw new AssertionError("Large HTTP headers");
    }
}
