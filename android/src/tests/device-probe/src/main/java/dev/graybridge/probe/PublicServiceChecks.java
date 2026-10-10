package dev.graybridge.probe;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.os.SystemClock;
import android.util.Base64;
import org.json.JSONArray;
import org.json.JSONObject;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.GZIPInputStream;

/** Real public requests from the separate probe UID. No login, cookies, or user data. */
final class PublicServiceChecks {
    private static final int MAX_BODY=65536;
    private final long deadline=SystemClock.elapsedRealtime()+60000;
    private final AtomicBoolean cancelled=new AtomicBoolean();
    private final Set<Socket> sockets=ConcurrentHashMap.newKeySet();

    static JSONObject run(Context context) throws Exception {
        return new PublicServiceChecks().execute(context);
    }

    private JSONObject execute(Context context) throws Exception {
        ConnectivityManager manager=context.getSystemService(ConnectivityManager.class);
        NetworkCapabilities caps=manager.getNetworkCapabilities(manager.getActiveNetwork());
        if(caps==null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
            throw new IOException("VPN is not active for the probe UID");
        List<Check> checks=Arrays.asList(
            new Check("YouTube", "www.youtube.com", "/generate_204", "youtube"),
            new Check("Discord API", "discord.com", "/api/v10/gateway", "discord_api"),
            new Check("Discord CDN", "cdn.discordapp.com", "/embed/avatars/0.png", "discord_cdn"),
            new Check("Discord Gateway", "gateway.discord.gg", "/?v=10&encoding=json", "discord_wss"),
            new Check("Instagram", "www.instagram.com", "/", "page"),
            new Check("ChatGPT public page", "chatgpt.com", "/", "page"),
            new Check("ChatGPT OAuth providers", "chatgpt.com", "/api/auth/providers", "providers"));
        ExecutorService workers=Executors.newFixedThreadPool(checks.size(), task->{
            Thread thread=new Thread(task,"public-service-probe");thread.setDaemon(true);return thread;
        });
        List<Future<JSONObject>> pending=new ArrayList<>();
        JSONArray results=new JSONArray();
        int passed=0;
        try {
            for(Check check:checks)pending.add(workers.submit(check));
            for(int i=0;i<checks.size();i++) {
                JSONObject result;
                try {result=pending.get(i).get(Math.max(1,deadline-SystemClock.elapsedRealtime()),TimeUnit.MILLISECONDS);}
                catch(TimeoutException error) {result=checks.get(i).failure("timeout","DeadlineExceeded");}
                catch(ExecutionException error) {result=checks.get(i).failure("probe_error",error.getCause().getClass().getSimpleName());}
                results.put(result);
                if(result.optBoolean("ok"))passed++;
            }
        } finally {
            cancelled.set(true);
            for(Future<JSONObject> future:pending)future.cancel(true);
            for(Socket socket:sockets)try {socket.close();}catch(IOException ignored) { }
            workers.shutdownNow();
        }
        return new JSONObject().put("result",passed==checks.size()?"PASS":"PARTIAL")
            .put("passed",passed).put("total",checks.size()).put("checks",results)
            .put("vpn_active_for_probe_uid",true).put("system_dns",true)
            .put("certificate_validation_required",true).put("hostname_validation_required",true)
            .put("authenticated_access",false).put("elapsed_ms",60000-(deadline-SystemClock.elapsedRealtime()))
            .put("checked_at_epoch_ms",System.currentTimeMillis())
            .put("scope","Fixed public requests only; no account, chat, video playback, media download, or voice-call validation");
    }

    private int remaining(long end,int maximum) throws SocketTimeoutException {
        long left=Math.min(deadline,end)-SystemClock.elapsedRealtime();
        if(cancelled.get() || Thread.currentThread().isInterrupted() || left<=0)throw new SocketTimeoutException("Probe deadline");
        return (int)Math.max(1,Math.min(maximum,left));
    }

    private final class Check implements Callable<JSONObject> {
        final String name,host,path,kind;
        volatile String stage="DNS";
        final long started=SystemClock.elapsedRealtime();
        Check(String name,String host,String path,String kind) {this.name=name;this.host=host;this.path=path;this.kind=kind;}
        JSONObject base() throws Exception {
            return new JSONObject().put("service",name).put("url",(kind.equals("discord_wss")?"wss":"https")+"://"+host+path)
                .put("ok",false).put("authenticated_access",false);
        }
        JSONObject failure(String state,String error) throws Exception {
            return base().put("state",state).put("stage",stage).put("error",error)
                .put("elapsed_ms",SystemClock.elapsedRealtime()-started);
        }
        @Override public JSONObject call() throws Exception {
            JSONObject result=base();
            long end=SystemClock.elapsedRealtime()+25000;
            Socket raw=null;SSLSocket tls=null;
            try {
                // Resolve with Android's ordinary network DNS, as any VPN-covered app does.
                InetAddress[] addresses=InetAddress.getAllByName(host);
                remaining(end,6000);
                JSONArray dns=new JSONArray();for(InetAddress address:addresses)dns.put(address.getHostAddress());
                result.put("dns_addresses",dns).put("dns_ms",SystemClock.elapsedRealtime()-started);
                List<InetAddress> candidates=new ArrayList<>(Arrays.asList(addresses));
                candidates.sort(Comparator.comparingInt(address->address instanceof Inet4Address?0:1));
                stage="TCP";
                IOException last=null;
                for(int i=0;i<Math.min(4,candidates.size());i++) {
                    remaining(end,6000);
                    raw=new Socket();sockets.add(raw);
                    try {
                        raw.connect(new InetSocketAddress(candidates.get(i),443),remaining(end,6000));
                        result.put("connected_address",candidates.get(i).getHostAddress());break;
                    } catch(IOException error) {
                        last=error;raw.close();sockets.remove(raw);raw=null;
                    }
                }
                if(raw==null)throw last==null?new IOException("No DNS addresses"):last;
                stage="TLS";
                raw.setSoTimeout(remaining(end,7000));
                tls=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(raw,host,443,true);
                sockets.add(tls);
                SSLParameters parameters=tls.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");tls.setSSLParameters(parameters);
                tls.setSoTimeout(remaining(end,7000));tls.startHandshake();
                result.put("certificate_chain_verified",true).put("hostname_verified",true)
                    .put("tls_protocol",tls.getSession().getProtocol()).put("tls_ms",SystemClock.elapsedRealtime()-started);
                stage="HTTP";tls.setSoTimeout(remaining(end,7000));
                if(kind.equals("discord_wss"))checkWebSocket(tls,result);
                else {
                    tls.getOutputStream().write(("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nAccept: */*\r\nAccept-Encoding: identity\r\nUser-Agent: SorryRKN-ServiceCheck\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    InputStream input=tls.getInputStream();Response response=readHead(input);
                    result.put("http_status",response.status);readBody(input,response);
                    classify(response,result);
                }
            } catch(Exception error) {
                result.put("ok",false).put("state",error instanceof SocketTimeoutException?"timeout":"transport_error")
                    .put("error",error.getClass().getSimpleName());
            } finally {
                if(tls!=null) {try {tls.close();}catch(IOException ignored) { }sockets.remove(tls);}
                if(raw!=null) {try {raw.close();}catch(IOException ignored) { }sockets.remove(raw);}
            }
            return result.put("stage",stage).put("elapsed_ms",SystemClock.elapsedRealtime()-started);
        }

        private void classify(Response response,JSONObject result) throws Exception {
            result.put("http_status",response.status).put("body_bytes_examined",response.body.length)
                .put("body_truncated",response.truncated).put("content_type",response.headers.getOrDefault("content-type",""));
            String state=pageState(response);
            boolean ok=false;
            if(state.equals("reachable_public")) {
                if(kind.equals("youtube"))ok=response.status==204 && response.body.length==0;
                else if(kind.equals("discord_api")) {
                    try {ok=!response.truncated && parseObject(response.body).optString("url").equals("wss://gateway.discord.gg");}
                    catch(Exception invalid) { }
                } else if(kind.equals("discord_cdn")) {
                    byte[] signature={(byte)137,80,78,71,13,10,26,10};
                    ok=response.headers.getOrDefault("content-type","").split(";")[0].equalsIgnoreCase("image/png")
                        && response.body.length>=signature.length && Arrays.equals(Arrays.copyOf(response.body,signature.length),signature);
                } else if(kind.equals("providers")) {
                    try {
                        JSONObject provider=parseObject(response.body).getJSONObject("openai");
                        ok=!response.truncated && response.headers.getOrDefault("content-type","").split(";",2)[0].trim().equalsIgnoreCase("application/json")
                            && provider.getString("id").equals("openai") && provider.getString("type").equals("oauth");
                    } catch(Exception invalid) { }
                    if(ok)state="verified_public_oauth_metadata";
                } else {
                    String body=new String(response.body,StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
                    ok=response.status==200 && response.headers.getOrDefault("content-type","").toLowerCase(Locale.ROOT).contains("text/html")
                        && (body.contains("<html") || body.contains("<!doctype html"));
                }
                if(!ok)state="invalid_response";
            }
            result.put("ok",ok).put("state",state);
            String location=response.headers.get("location");
            if(location!=null) {
                // Report only the public redirect origin/path, never query/cookie values.
                try {URI uri=new URI("https://"+host+path).resolve(location);result.put("redirect",uri.getScheme()+"://"+uri.getHost()+uri.getPath());}
                catch(URISyntaxException ignored) {result.put("redirect","invalid");}
            }
        }

        private void checkWebSocket(SSLSocket tls,JSONObject result) throws Exception {
            byte[] nonce=new byte[16];new SecureRandom().nextBytes(nonce);
            String key=Base64.encodeToString(nonce,Base64.NO_WRAP);
            tls.getOutputStream().write(("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "+key+"\r\nSec-WebSocket-Version: 13\r\nUser-Agent: SorryRKN-ServiceCheck\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            InputStream input=tls.getInputStream();Response response=readHead(input);
            result.put("http_status",response.status);
            if(response.status!=101) {
                readBody(input,response);result.put("state",pageState(response));return;
            }
            stage="WebSocket";
            String accept=Base64.encodeToString(MessageDigest.getInstance("SHA-1").digest((key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.US_ASCII)),Base64.NO_WRAP);
            if(!response.headers.getOrDefault("upgrade","").equalsIgnoreCase("websocket")
                || !Arrays.asList(response.headers.getOrDefault("connection","").toLowerCase(Locale.ROOT).split("\\s*,\\s*")).contains("upgrade")
                || !response.headers.getOrDefault("sec-websocket-accept","").equals(accept))throw new IOException("Invalid WebSocket upgrade");
            DataInputStream data=new DataInputStream(input);
            int opcode=data.readUnsignedByte(),length=data.readUnsignedByte();
            if(opcode!=0x81 || (length&128)!=0)throw new IOException("Invalid server Hello frame");
            long size=length;
            if(length==126)size=data.readUnsignedShort();
            else if(length==127)size=data.readLong();
            if(size<1 || size>16384)throw new IOException("Invalid Hello length");
            byte[] body=new byte[(int)size];data.readFully(body);
            JSONObject hello=new JSONObject(new String(body,StandardCharsets.UTF_8));
            if(hello.getInt("op")!=10 || hello.getJSONObject("d").getLong("heartbeat_interval")<=0)throw new IOException("Invalid Discord Hello");
            result.put("ok",true).put("state","verified_gateway_hello");
            // Masked close(1000); no Identify, token, heartbeat, or user session is sent.
            try {tls.getOutputStream().write(new byte[]{(byte)0x88,(byte)0x82,1,2,3,4,2,(byte)0xea});}
            catch(IOException ignored) { } // The verified Hello already completed the observational check.
        }
    }

    private static String pageState(Response response) {
        String body=new String(response.body,StandardCharsets.UTF_8),lower=body.toLowerCase(Locale.ROOT);
        String visible=lower.replaceAll("(?is)<(script|style)\\b[^>]*>.*?(?:</\\1\\s*>|$)"," ")
            .replaceAll("(?s)<!--.*?(?:-->|$)"," ").replaceAll("<[^>]*>"," ").replaceAll("\\s+"," ").trim();
        String code="unsupported_country_region_territory";
        try {
            JSONObject json=parseObject(response.body);Object error=json.opt("error");
            if(code.equals(error))return "regional_refusal";
            JSONObject value=error instanceof JSONObject?(JSONObject)error:json;
            if(code.equals(value.optString("code")) || code.equals(value.optString("type")))return "regional_refusal";
            if(regionalText(value.optString("message")))return "regional_refusal";
        } catch(Exception ignored) { }
        if(visible.equals(code) || regionalText(visible))return "regional_refusal";
        if(response.headers.getOrDefault("cf-mitigated","").equalsIgnoreCase("challenge")
            || (lower.contains("cf-chl-") || lower.contains("/cdn-cgi/challenge-platform/"))
                && (visible.contains("just a moment") || visible.contains("checking your browser") || visible.contains("verify you are human")))return "challenge";
        if(response.status==403)return "denied";
        if(response.status>=300 && response.status<400)return "redirect_unchecked";
        return response.status==200 || response.status==204?"reachable_public":"http_error";
    }

    private static boolean regionalText(String text) {
        return text.toLowerCase(Locale.ROOT).matches("(?s).*(?:country,?\\s*region,?\\s*(?:or\\s*)?territory\\s+(?:is\\s+)?not supported|(?:openai(?:'s)?(?: services)?|chatgpt|this service)\\s+(?:is|are)\\s+not available in your (?:country|region)|(?:your|this) (?:country|region) (?:is not supported|is unsupported)).*");
    }
    private static JSONObject parseObject(byte[] bytes) throws Exception {
        org.json.JSONTokener tokens=new org.json.JSONTokener(new String(bytes,StandardCharsets.UTF_8));
        Object value=tokens.nextValue();
        if(!(value instanceof JSONObject) || tokens.nextClean()!=0)throw new IOException("Invalid JSON document");
        return (JSONObject)value;
    }

    private static final class Response {
        int status;Map<String,String> headers=new HashMap<>();byte[] body=new byte[0];boolean truncated;
    }
    private static Response readHead(InputStream input) throws Exception {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();int tail=0;
        while(bytes.size()<32768) {
            int value=input.read();if(value<0)throw new EOFException("Short HTTP headers");
            bytes.write(value);tail=(tail<<8)|value;
            if(tail==0x0d0a0d0a) {
                String[] lines=bytes.toString("US-ASCII").split("\r\n");
                if(!lines[0].matches("HTTP/1\\.[01] [0-9]{3}(?: .*|)"))throw new IOException("Invalid status line");
                Response result=new Response();result.status=Integer.parseInt(lines[0].substring(9,12));
                for(int i=1;i<lines.length;i++) {int split=lines[i].indexOf(':');if(split>0)result.headers.put(lines[i].substring(0,split).toLowerCase(Locale.ROOT),lines[i].substring(split+1).trim());}
                return result;
            }
        }
        throw new IOException("Oversized HTTP headers");
    }
    private static void readBody(InputStream input,Response response) throws Exception {
        if(response.status==204 || response.status==304)return;
        String transfer=response.headers.getOrDefault("transfer-encoding","");
        if(transfer.equalsIgnoreCase("chunked"))input=new ChunkedBody(input);
        else if(!transfer.isEmpty() && !transfer.equalsIgnoreCase("identity"))throw new IOException("Unsupported transfer coding");
        else if(response.headers.containsKey("content-length"))input=new SizedBody(input,Long.parseLong(response.headers.get("content-length")));
        input=new SizedBody(input,262144,false);
        String encoding=response.headers.getOrDefault("content-encoding","");
        if(encoding.equalsIgnoreCase("gzip"))input=new GZIPInputStream(input);
        else if(!encoding.isEmpty() && !encoding.equalsIgnoreCase("identity"))throw new IOException("Unsupported content encoding");
        ByteArrayOutputStream body=new ByteArrayOutputStream();byte[] buffer=new byte[4096];int count;
        while(body.size()<=MAX_BODY && (count=input.read(buffer,0,Math.min(buffer.length,MAX_BODY+1-body.size())))!=-1)body.write(buffer,0,count);
        response.truncated=body.size()>MAX_BODY;
        response.body=Arrays.copyOf(body.toByteArray(),Math.min(body.size(),MAX_BODY));
    }
    private static final class SizedBody extends FilterInputStream {
        long left;final boolean strict;
        SizedBody(InputStream input,long size) throws IOException {this(input,size,true);}
        SizedBody(InputStream input,long size,boolean strict) throws IOException {super(input);if(size<0)throw new IOException("Negative body size");left=size;this.strict=strict;}
        @Override public int read() throws IOException {if(left==0)return -1;int value=super.read();if(value<0) {if(strict)throw new EOFException("Short response body");left=0;return -1;}left--;return value;}
        @Override public int read(byte[] buffer,int offset,int length) throws IOException {
            if(length==0)return 0;
            if(left==0)return -1;int count=in.read(buffer,offset,(int)Math.min(left,length));
            if(count<0) {if(strict)throw new EOFException("Short response body");left=0;return -1;}left-=count;return count;
        }
    }
    private static final class ChunkedBody extends FilterInputStream {
        long left;boolean first=true,done;
        ChunkedBody(InputStream input) {super(input);}
        private void next() throws IOException {
            if(!first && (in.read()!=13 || in.read()!=10))throw new IOException("Invalid chunk ending");first=false;
            ByteArrayOutputStream line=new ByteArrayOutputStream();
            while(line.size()<128) {int value=in.read();if(value<0)throw new EOFException("Short chunk size");if(value==13) {if(in.read()!=10)throw new IOException("Invalid chunk size");break;}line.write(value);}
            if(line.size()>=128)throw new IOException("Oversized chunk size");
            try {left=Long.parseLong(line.toString("US-ASCII").split(";",2)[0],16);}catch(NumberFormatException error) {throw new IOException("Invalid chunk size");}
            if(left<0 || left>16777216)throw new IOException("Invalid chunk size");done=left==0;
        }
        @Override public int read() throws IOException {byte[] one=new byte[1];return read(one,0,1)<0?-1:one[0]&255;}
        @Override public int read(byte[] buffer,int offset,int length) throws IOException {
            if(length==0)return 0;
            if(done)return -1;if(left==0)next();if(done)return -1;
            int count=in.read(buffer,offset,(int)Math.min(left,length));if(count<0)throw new EOFException("Short chunk");left-=count;return count;
        }
    }
}
