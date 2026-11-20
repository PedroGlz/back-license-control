package com.etic.licensecontrol.auth;

import com.etic.licensecontrol.licensing.MailService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class PasswordRecoveryOutboxService {
    private static final Logger log=LoggerFactory.getLogger(PasswordRecoveryOutboxService.class);
    private static final SecureRandom RANDOM=new SecureRandom();
    private final NamedParameterJdbcTemplate db;private final MailService mail;private final TransactionTemplate tx;private final byte[] key;

    PasswordRecoveryOutboxService(NamedParameterJdbcTemplate db,MailService mail,PlatformTransactionManager manager,
            @Value("${license-control.password-recovery.outbox-key:}") String configuredKey){
        this.db=db;this.mail=mail;this.tx=new TransactionTemplate(manager);this.key=configuredKey==null||configuredKey.length()<32?null:deriveKey(configuredKey);
    }

    public void enqueue(String outboxId,String requestId,String userId,String system,String email,String name,String password,
            Instant deliveryExpires,Instant credentialExpires,String previousHash,boolean previousMustChange,Object previousTemporaryExpires,int issuedAuthVersion,String issuedHash){
        String encrypted=encrypt(password);
        var p=new org.springframework.jdbc.core.namedparam.MapSqlParameterSource()
            .addValue("id",outboxId).addValue("request",requestId).addValue("user",userId).addValue("system",system)
            .addValue("email",email).addValue("name",name).addValue("secret",encrypted).addValue("expires",LocalDateTime.ofInstant(deliveryExpires,ZoneOffset.UTC)).addValue("credentialExpires",LocalDateTime.ofInstant(credentialExpires,ZoneOffset.UTC))
            .addValue("previousHash",previousHash).addValue("previousMust",previousMustChange).addValue("previousExpires",previousTemporaryExpires)
            .addValue("issuedVersion",issuedAuthVersion).addValue("issuedHash",issuedHash);
        db.update("INSERT INTO password_recovery_outbox(Id_Outbox,Id_Request,Id_User,Requested_System,Recipient_Email,Recipient_Name,Encrypted_Secret,Expires_At,Credential_Expires_At,Previous_Password_Hash,Previous_Must_Change_Password,Previous_Temporary_Password_Expires_At,Issued_Auth_Version,Issued_Password_Hash,Status,Next_Attempt_At) VALUES(:id,:request,:user,:system,:email,:name,:secret,:expires,:credentialExpires,:previousHash,:previousMust,:previousExpires,:issuedVersion,:issuedHash,'PENDING',UTC_TIMESTAMP(6))",p);
    }

    public void prepareReplacement(String userId){
        var rows=db.queryForList("SELECT * FROM password_recovery_outbox WHERE Id_User=:user AND Status IN ('PENDING','FAILED','PROCESSING') FOR UPDATE",Map.of("user",userId));
        for(var row:rows){restorePassword(row);clearTerminal(row,"SUPERSEDED","CREDENTIAL_REPLACED");}
    }

    @Scheduled(fixedDelayString="${license-control.password-recovery.outbox-poll-ms:5000}")
    public void dispatch(){
        try{recoverStale();expireSecrets();for(int i=0;i<10;i++){var message=claim();if(message==null)break;deliver(message);}}
        catch(Exception ex){log.error("No fue posible procesar el outbox de recuperación. Tipo={}",ex.getClass().getSimpleName());}
    }

    private void recoverStale(){db.update("UPDATE password_recovery_outbox SET Status='FAILED',Locked_At=NULL,Next_Attempt_At=UTC_TIMESTAMP(6),Last_Error_Code='WORKER_INTERRUPTED' WHERE Status='PROCESSING' AND Locked_At<DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 5 MINUTE)",Map.of());}

    private Map<String,Object> claim(){
        return tx.execute(status->{
            var rows=db.queryForList("SELECT * FROM password_recovery_outbox WHERE Status IN ('PENDING','FAILED') AND Encrypted_Secret IS NOT NULL AND Expires_At>UTC_TIMESTAMP(6) AND Next_Attempt_At<=UTC_TIMESTAMP(6) ORDER BY Created_At LIMIT 1 FOR UPDATE SKIP LOCKED",Map.of());
            if(rows.isEmpty())return null;var row=rows.getFirst();
            db.update("UPDATE password_recovery_outbox SET Status='PROCESSING',Locked_At=UTC_TIMESTAMP(6),Attempt_Count=Attempt_Count+1 WHERE Id_Outbox=:id",Map.of("id",row.get("Id_Outbox")));
            row.put("Attempt_Count",((Number)row.get("Attempt_Count")).intValue()+1);return row;
        });
    }

    private void deliver(Map<String,Object> claimed){
        tx.executeWithoutResult(status->{
            String id=claimed.get("Id_Outbox").toString(),userId=claimed.get("Id_User").toString();
            db.queryForList("SELECT Id_User FROM users WHERE Id_User=:user FOR UPDATE",Map.of("user",userId));
            var rows=db.queryForList("SELECT * FROM password_recovery_outbox WHERE Id_Outbox=:id AND Status='PROCESSING' FOR UPDATE",Map.of("id",id));
            if(rows.isEmpty())return;var row=rows.getFirst();
            Integer current=db.queryForObject("SELECT COUNT(*) FROM users WHERE Id_User=:user AND BINARY Password_Hash=BINARY :issued AND Auth_Version=:version",Map.of("user",userId,"issued",row.get("Issued_Password_Hash"),"version",row.get("Issued_Auth_Version")),Integer.class);
            if(current==null||current==0){clearTerminal(row,"SUPERSEDED","CREDENTIAL_REPLACED");return;}
            if(!instant(row.get("Expires_At")).isAfter(Instant.now())){restorePassword(row);clearTerminal(row,"EXPIRED","DELIVERY_EXPIRED");return;}
            String password;
            try{password=decrypt(row.get("Encrypted_Secret").toString());}
            catch(Exception ex){restorePassword(row);clearTerminal(row,"EXPIRED","SECRET_UNREADABLE");return;}
            boolean sent=mail.sendTemporaryPassword(row.get("Recipient_Email").toString(),Objects.toString(row.get("Recipient_Name"),""),password,instant(row.get("Credential_Expires_At")),row.get("Requested_System").toString());
            if(sent){
                db.update("UPDATE password_recovery_outbox SET Status='SENT',Sent_At=UTC_TIMESTAMP(6),Locked_At=NULL,Encrypted_Secret=NULL,Previous_Password_Hash=NULL,Issued_Password_Hash=NULL,Last_Error_Code=NULL WHERE Id_Outbox=:id AND Status='PROCESSING'",Map.of("id",id));
                db.update("UPDATE password_reset_requests SET Notified_At=UTC_TIMESTAMP(6) WHERE Id_Request=:request",Map.of("request",row.get("Id_Request")));
            }else{
                int attempts=((Number)row.get("Attempt_Count")).intValue();long delay=Math.min(300L,5L*(1L<<Math.min(attempts,6)));
                db.update("UPDATE password_recovery_outbox SET Status='FAILED',Locked_At=NULL,Next_Attempt_At=:next,Last_Error_Code='SMTP_DELIVERY_FAILED' WHERE Id_Outbox=:id AND Status='PROCESSING'",Map.of("next",LocalDateTime.now(ZoneOffset.UTC).plusSeconds(delay),"id",id));
            }
        });
    }

    private void expireSecrets(){
        for(int i=0;i<50;i++){
            var candidates=db.queryForList("SELECT Id_Outbox,Id_User FROM password_recovery_outbox WHERE Status IN ('PENDING','FAILED','PROCESSING') AND Expires_At<=UTC_TIMESTAMP(6) ORDER BY Expires_At LIMIT 1",Map.of());
            if(candidates.isEmpty())break;var candidate=candidates.getFirst();
            Boolean changed=tx.execute(status->{
                db.queryForList("SELECT Id_User FROM users WHERE Id_User=:user FOR UPDATE",Map.of("user",candidate.get("Id_User")));
                var rows=db.queryForList("SELECT * FROM password_recovery_outbox WHERE Id_Outbox=:id AND Status IN ('PENDING','FAILED','PROCESSING') AND Expires_At<=UTC_TIMESTAMP(6) FOR UPDATE",Map.of("id",candidate.get("Id_Outbox")));
                if(rows.isEmpty())return false;var row=rows.getFirst();restorePassword(row);clearTerminal(row,"EXPIRED","DELIVERY_EXPIRED");return true;
            });
            if(!Boolean.TRUE.equals(changed))break;
        }
    }

    private void restorePassword(Map<String,Object> row){
        var p=new org.springframework.jdbc.core.namedparam.MapSqlParameterSource().addValue("user",row.get("Id_User")).addValue("previous",row.get("Previous_Password_Hash"))
            .addValue("previousMust",row.get("Previous_Must_Change_Password")).addValue("previousExpires",row.get("Previous_Temporary_Password_Expires_At"))
            .addValue("issued",row.get("Issued_Password_Hash")).addValue("version",row.get("Issued_Auth_Version"));
        db.update("UPDATE users SET Password_Hash=:previous,Must_Change_Password=:previousMust,Temporary_Password_Expires_At=:previousExpires,Auth_Version=Auth_Version+1,Password_Changed_At=UTC_TIMESTAMP(6) WHERE Id_User=:user AND BINARY Password_Hash=BINARY :issued AND Auth_Version=:version AND Temporary_Password_Expires_At>UTC_TIMESTAMP(6)",p);
    }

    private void clearTerminal(Map<String,Object> row,String terminalStatus,String code){
        db.update("UPDATE password_recovery_outbox SET Status=:status,Encrypted_Secret=NULL,Previous_Password_Hash=NULL,Issued_Password_Hash=NULL,Locked_At=NULL,Last_Error_Code=:code WHERE Id_Outbox=:id",Map.of("id",row.get("Id_Outbox"),"status",terminalStatus,"code",code));
        db.update("UPDATE password_reset_requests SET Status='EXPIRED' WHERE Id_Request=:request AND Status='COMPLETED'",Map.of("request",row.get("Id_Request")));
    }

    private String encrypt(String value){
        if(key==null)throw new IllegalStateException("Configurar PASSWORD_RECOVERY_OUTBOX_KEY o LICENSE_CONTROL_JWT_SECRET con al menos 32 caracteres");
        try{byte[] nonce=new byte[12];RANDOM.nextBytes(nonce);Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));byte[] encrypted=cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));byte[] packed=new byte[nonce.length+encrypted.length];System.arraycopy(nonce,0,packed,0,nonce.length);System.arraycopy(encrypted,0,packed,nonce.length,encrypted.length);return Base64.getEncoder().encodeToString(packed);}catch(Exception ex){throw new IllegalStateException("No fue posible proteger la credencial temporal",ex);}
    }
    private String decrypt(String value)throws Exception{if(key==null)throw new IllegalStateException("OUTBOX_KEY_UNAVAILABLE");byte[] packed=Base64.getDecoder().decode(value);if(packed.length<29)throw new IllegalArgumentException();byte[] nonce=Arrays.copyOfRange(packed,0,12),encrypted=Arrays.copyOfRange(packed,12,packed.length);Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));return new String(cipher.doFinal(encrypted),StandardCharsets.UTF_8);}
    private static byte[] deriveKey(String value){try{return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));}catch(java.security.NoSuchAlgorithmException ex){throw new IllegalStateException(ex);}}
    private static Instant instant(Object value){if(value instanceof java.sql.Timestamp t)return t.toLocalDateTime().toInstant(ZoneOffset.UTC);if(value instanceof LocalDateTime t)return t.toInstant(ZoneOffset.UTC);return Instant.parse(value.toString());}
}
