package com.etic.licensecontrol.auth;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import tools.jackson.databind.json.JsonMapper;

@Service
public class JwtService {
    private final byte[] secret; private final long expiration;
    private final JsonMapper json=JsonMapper.builder().build();
    JwtService(@Value("${license-control.jwt.secret}") String value, @Value("${license-control.jwt.expiration-seconds}") long expiration) {
        if (value == null || value.length() < 32) throw new IllegalStateException("LICENSE_CONTROL_JWT_SECRET debe contener al menos 32 caracteres");
        this.secret=value.getBytes(StandardCharsets.UTF_8); this.expiration=expiration;
    }
    String create(String userId) { long now=Instant.now().getEpochSecond(); String header=part("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");String payload=part("{\"sub\":\""+userId+"\",\"iat\":"+now+",\"exp\":"+(now+expiration)+"}");return sign(header+"."+payload); }
    String subject(String token) { try { String[] parts=token.split("\\.");if(parts.length!=3||!constant(parts[2],signature(parts[0]+"."+parts[1])))return null;var header=json.readTree(Base64.getUrlDecoder().decode(parts[0]));if(!"HS256".equals(header.path("alg").asText()))return null;var claims=json.readTree(Base64.getUrlDecoder().decode(parts[1]));String sub=claims.path("sub").asText();return !sub.isBlank()&&claims.path("exp").asLong()>Instant.now().getEpochSecond()?sub:null;}catch(Exception e){return null;} }
    private String part(String value){return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));}
    private String sign(String v){return v+"."+signature(v);} private String signature(String v){try{Mac m=Mac.getInstance("HmacSHA256");m.init(new SecretKeySpec(secret,"HmacSHA256"));return Base64.getUrlEncoder().withoutPadding().encodeToString(m.doFinal(v.getBytes(StandardCharsets.UTF_8)));}catch(Exception e){throw new IllegalStateException(e);}}
    private boolean constant(String a,String b){return java.security.MessageDigest.isEqual(a.getBytes(StandardCharsets.US_ASCII),b.getBytes(StandardCharsets.US_ASCII));}
}
