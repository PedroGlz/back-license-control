package com.etic.licensecontrol.licensing;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.databind.json.JsonMapper;

/** P-256 / SHA256withECDSA para pruebas de posesión y firma offline. */
@Service
public class DeviceCrypto {
    private final SecureRandom random = new SecureRandom();
    private final String keyPath, keyId, configuredKey;
    private final JsonMapper json = JsonMapper.builder().build();
    public DeviceCrypto(@Value("${license-control.offline.private-key-path:}") String keyPath,
                        @Value("${license-control.offline.key-id:lc-device-v1}") String keyId,
                        @Value("${LICENSING_SIGNING_PRIVATE_KEY:}") String configuredKey) {
        this.keyPath=keyPath; this.keyId=keyId; this.configuredKey=configuredKey;
    }
    public String randomToken() { byte[] bytes=new byte[32]; random.nextBytes(bytes); return encode(bytes); }
    public static String hash(String value) { return hash(value.getBytes(StandardCharsets.UTF_8)); }
    public static String hash(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (GeneralSecurityException ex) { throw new IllegalStateException(ex); }
    }
    public ECPublicKey publicKey(String value) {
        try {
            if(value==null||value.length()>2048)throw new InvalidKeyException();
            var key=(ECPublicKey)KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(decodePem(value,"PUBLIC KEY")));
            requireP256(key.getParams()); return key;
        } catch (GeneralSecurityException|IllegalArgumentException|ClassCastException ex) {
            throw new IllegalArgumentException("La clave pública debe usar EC P-256");
        }
    }
    private static void requireP256(ECParameterSpec actual) throws GeneralSecurityException {
        var parameters=AlgorithmParameters.getInstance("EC"); parameters.init(new ECGenParameterSpec("secp256r1"));
        var expected=parameters.getParameterSpec(ECParameterSpec.class);
        if(!actual.getCurve().equals(expected.getCurve())||!actual.getGenerator().equals(expected.getGenerator())
            ||!actual.getOrder().equals(expected.getOrder())||actual.getCofactor()!=expected.getCofactor())throw new InvalidKeyException();
    }
    public boolean verify(String key,byte[] payload,String signature) {
        try {
            if(signature==null||signature.length()>256)return false;
            var verifier=Signature.getInstance("SHA256withECDSA"); verifier.initVerify(publicKey(key)); verifier.update(payload);
            return verifier.verify(Base64.getDecoder().decode(signature));
        } catch (GeneralSecurityException|IllegalArgumentException ex) { return false; }
    }
    public String issue(Map<String,Object> claims) {
        try {
            if(keyPath.isBlank()&&configuredKey.isBlank())throw new InvalidKeyException("Offline signing key not configured");
            String pem=keyPath.isBlank()?configuredKey:Files.readString(Path.of(keyPath));
            var key=(ECPrivateKey)KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(decodePem(pem,"PRIVATE KEY")));
            requireP256(key.getParams());
            String input=encode(json.writeValueAsBytes(Map.of("alg","ES256","typ","LC-OFFLINE-LICENSE","kid",keyId)))+"."+encode(json.writeValueAsBytes(claims));
            var signer=Signature.getInstance("SHA256withECDSAinP1363Format"); signer.initSign(key); signer.update(input.getBytes(StandardCharsets.US_ASCII));
            return input+"."+encode(signer.sign());
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"No fue posible firmar la credencial offline. Consulta al administrador.",ex);
        }
    }
    private static byte[] decodePem(String value,String type) { return Base64.getDecoder().decode(value.replace("-----BEGIN "+type+"-----","").replace("-----END "+type+"-----","").replaceAll("\\s", "")); }
    private static String encode(byte[] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
}
