package dev.graybridge;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.json.JSONObject;
import java.io.IOException;

/** Only the public update key is shipped. APK signing identity is independent. */
public final class UpdateTrust {
    static final String KEY_ID="f3f23cac9a5a73ef38b20d1241d58593";
    static final String PUBLIC_KEY="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7AmTEFFzgovjJELjmL/+Vi+XrWL8tR/F0sRXc+amKKY42tRbPiQ1SWn+OlGT49EvJGqTW3ZaHmKv3lrResGtHA==";
    public static String payload(String text) throws Exception {
        return verified(new JSONObject(text)).toString();
    }
    static JSONObject verified(JSONObject value) throws Exception {
        return verifiedAt(value,System.currentTimeMillis()/1000);
    }
    static JSONObject verifiedAt(JSONObject value,long now) throws Exception {
        if(!KEY_ID.equals(value.optString("keyId")))throw new IOException("Неизвестный ключ обновления");
        long signedAt=value.getLong("signedAt"),expires=value.getLong("expires");
        if(signedAt>now+300 || expires<=now || expires<=signedAt || expires-signedAt>366L*86400)
            throw new IOException("Срок подписи истёк или неверно время устройства");
        String encoded=value.getString("signed");
        if(encoded.length()>60000)throw new IOException("Данные слишком большие");
        String message="SorryRKN-Envelope-v1\n"+KEY_ID+"\n"+signedAt+"\n"+expires+"\n"+encoded;
        PublicKey key=KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY)));
        java.security.Signature check=java.security.Signature.getInstance("SHA256withECDSA");
        check.initVerify(key);check.update(message.getBytes(StandardCharsets.UTF_8));
        if(!check.verify(Base64.getDecoder().decode(value.getString("signature"))))throw new IOException("Подпись обновления не совпадает");
        return new JSONObject(new String(Base64.getDecoder().decode(encoded),StandardCharsets.UTF_8));
    }
}
