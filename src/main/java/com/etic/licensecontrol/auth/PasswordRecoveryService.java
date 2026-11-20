package com.etic.licensecontrol.auth;

import com.etic.licensecontrol.licensing.MailService;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class PasswordRecoveryService {
    private static final Logger log = LoggerFactory.getLogger(PasswordRecoveryService.class);
    private static final String GENERIC = "Si los datos corresponden a una cuenta registrada, recibirás una contraseña temporal en el correo configurado.";
    private static final Duration REQUEST_WINDOW = Duration.ofMinutes(15);
    private static final SecureRandom RANDOM = new SecureRandom();
    private final NamedParameterJdbcTemplate db; private final PasswordEncoder encoder; private final MailService mail; private final TransactionTemplate tx;
    private final ConcurrentMap<String,Instant> requestLimits = new ConcurrentHashMap<>();
    private final ConcurrentMap<String,DeliverySecret> deliveries = new ConcurrentHashMap<>();
    private record DeliverySecret(String userId,String requestId,String adminId,String password,String email,String name,Instant expires,AtomicBoolean sending) {}

    PasswordRecoveryService(NamedParameterJdbcTemplate db,PasswordEncoder encoder,MailService mail,PlatformTransactionManager manager){this.db=db;this.encoder=encoder;this.mail=mail;this.tx=new TransactionTemplate(manager);}

    public Map<String,Object> request(String identifier,String system){
        String key=Objects.toString(identifier,"").trim().toLowerCase(Locale.ROOT), source=Objects.toString(system,"ETIC_SUITE").trim().toUpperCase(Locale.ROOT);
        if(key.isBlank()||key.length()>254)return Map.of("message",GENERIC);
        if(!Set.of("ETIC_SUITE","ETIC_ONLINE","LICENSE_CONTROL").contains(source))return Map.of("message",GENERIC);
        Instant now=Instant.now(),allowed=requestLimits.get(key);if(allowed!=null&&allowed.isAfter(now))return Map.of("message",GENERIC);requestLimits.put(key,now.plus(REQUEST_WINDOW));
        expirePending();
        try { automaticReset(key,source,now); }
        catch (Exception ex) { log.error("No fue posible completar la recuperación automática. Sistema={}, tipo={}",source,ex.getClass().getSimpleName());queueForSupport(key,source,now); }
        return Map.of("message",GENERIC);
    }

    private void automaticReset(String key,String source,Instant requestedAt){
        tx.executeWithoutResult(status->{
            var users=db.queryForList("SELECT u.Id_User,u.Username,u.First_Name,u.Last_Name,u.Email FROM users u WHERE u.Is_Active=TRUE AND u.Status='ACTIVE' AND (LOWER(u.Username)=:key OR LOWER(u.Email)=:key) AND EXISTS (SELECT 1 FROM user_system_access a JOIN systems s ON s.Id_System=a.Id_System WHERE a.Id_User=u.Id_User AND a.Is_Active=TRUE AND a.Status='ACTIVE' AND s.Code=:system AND s.Is_Active=TRUE AND s.Status='ACTIVE') LIMIT 1 FOR UPDATE",Map.of("key",key,"system",source));
            if(users.isEmpty())return;
            var user=users.getFirst();String id=user.get("Id_User").toString(),email=Objects.toString(user.get("Email"),"").trim();
            if(!validEmail(email))throw new IllegalStateException("EMAIL_UNAVAILABLE");
            Integer recent=db.queryForObject("SELECT COUNT(*) FROM password_reset_requests WHERE Id_User=:user AND Status='COMPLETED' AND Requested_At>DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 15 MINUTE)",Map.of("user",id),Integer.class);
            if(recent!=null&&recent>0)return;
            String password=temporaryPassword(),request=UUID.randomUUID().toString();Instant expires=requestedAt.plus(REQUEST_WINDOW);
            db.update("UPDATE password_reset_requests SET Status='EXPIRED' WHERE Id_User=:user AND Status='PENDING'",Map.of("user",id));
            db.update("UPDATE users SET Password_Hash=:hash,Must_Change_Password=TRUE,Temporary_Password_Expires_At=:expires,Auth_Version=Auth_Version+1,Password_Changed_At=UTC_TIMESTAMP(6) WHERE Id_User=:id",Map.of("hash",encoder.encode(password),"expires",LocalDateTime.ofInstant(expires,ZoneOffset.UTC),"id",id));
            String name=(Objects.toString(user.get("First_Name"),"")+" "+Objects.toString(user.get("Last_Name"),"")).trim();
            if(!mail.sendTemporaryPassword(email,name,password,expires,source))throw new IllegalStateException("SMTP_DELIVERY_FAILED");
            db.update("INSERT INTO password_reset_requests(Id_Request,Id_User,Requested_System,Created_At,Expires_At,Requested_At,Status,Reset_At,Completed_At,Notified_At,Completed_By) VALUES(:request,:user,:system,UTC_TIMESTAMP(6),:expires,UTC_TIMESTAMP(6),'COMPLETED',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),:user)",Map.of("request",request,"user",id,"system",source,"expires",LocalDateTime.ofInstant(expires,ZoneOffset.UTC)));
            audit(id,id,"AUTOMATIC_PASSWORD_RESET");
        });
    }

    private void queueForSupport(String key,String source,Instant requestedAt){
        try {
            var users=db.queryForList("SELECT DISTINCT u.Id_User,u.Username,u.Email FROM users u JOIN user_system_access a ON a.Id_User=u.Id_User AND a.Is_Active=TRUE AND a.Status='ACTIVE' JOIN systems s ON s.Id_System=a.Id_System AND s.Code=:system AND s.Is_Active=TRUE AND s.Status='ACTIVE' WHERE u.Is_Active=TRUE AND u.Status='ACTIVE' AND (LOWER(u.Username)=:key OR LOWER(u.Email)=:key) LIMIT 1",Map.of("key",key,"system",source));
            if(users.isEmpty())return;
            var user=users.getFirst();String id=user.get("Id_User").toString();
            Integer pending=db.queryForObject("SELECT COUNT(*) FROM password_reset_requests WHERE Id_User=:user AND Status='PENDING'",Map.of("user",id),Integer.class);
            if(pending!=null&&pending>0)return;
            db.update("INSERT INTO password_reset_requests(Id_Request,Id_User,Requested_System,Created_At,Expires_At,Requested_At,Status) VALUES(:id,:user,:system,UTC_TIMESTAMP(6),DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 15 MINUTE),UTC_TIMESTAMP(6),'PENDING')",Map.of("id",UUID.randomUUID().toString(),"user",id,"system",source));
            var admins=db.queryForList("SELECT DISTINCT u.Email FROM users u JOIN user_system_access a ON a.Id_User=u.Id_User AND a.Is_Active=TRUE AND a.Status='ACTIVE' JOIN systems s ON s.Id_System=a.Id_System AND s.Code='LICENSE_CONTROL' AND s.Is_Active=TRUE JOIN user_system_roles ur ON ur.Id_User=u.Id_User AND ur.Id_System=s.Id_System AND ur.Is_Active=TRUE JOIN roles r ON r.Id_Role=ur.Id_Role AND r.Id_System=s.Id_System AND r.Code='SUPER_ADMIN' AND r.Is_Active=TRUE WHERE u.Is_Active=TRUE AND u.Status='ACTIVE' AND u.Email IS NOT NULL",Map.of(),String.class);
            mail.notifyPasswordResetAdmins(admins,Objects.toString(user.get("Username"),""),Objects.toString(user.get("Email"),""),source,requestedAt);
        } catch(Exception supportError){log.error("No fue posible registrar la recuperación para soporte. Sistema={}, tipo={}",source,supportError.getClass().getSimpleName());}
    }

    public List<Map<String,Object>> list(Authentication auth){requireSuperAdmin(auth);expirePending();var rows=db.queryForList("SELECT pr.Id_Request,pr.Id_User,u.Username,u.First_Name,u.Last_Name,u.Email,pr.Requested_System,pr.Status,pr.Created_At,pr.Expires_At,pr.Reset_At,pr.Completed_At,pr.Notified_At FROM password_reset_requests pr JOIN users u ON u.Id_User=pr.Id_User ORDER BY (pr.Status='PENDING') DESC,pr.Created_At DESC LIMIT 200",Map.of());for(var row:rows)for(String field:List.of("Created_At","Expires_At","Reset_At","Completed_At","Notified_At"))if(row.get(field)!=null)row.put(field,instant(row.get(field)));return rows;}

    public Map<String,Object> reset(String userId,String requestId,Authentication auth){requireSuperAdmin(auth);if(requestId==null||requestId.isBlank())throw new ResponseStatusException(HttpStatus.CONFLICT,"Se requiere una solicitud pendiente y vigente.");String admin=auth.getName();String password=temporaryPassword();
        var result=tx.execute(status->{var users=db.queryForList("SELECT Id_User,Username,First_Name,Last_Name,Email FROM users WHERE Id_User=:id AND Is_Active=TRUE FOR UPDATE",Map.of("id",userId));if(users.isEmpty())throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Usuario no encontrado.");var user=users.getFirst();
            var requests=db.queryForList("SELECT Id_Request,Expires_At FROM password_reset_requests WHERE Id_Request=:request AND Id_User=:user AND Status='PENDING' AND Reset_At IS NULL AND Expires_At>UTC_TIMESTAMP(6) FOR UPDATE",Map.of("request",requestId,"user",userId));if(requests.isEmpty()){expirePending();throw new ResponseStatusException(HttpStatus.GONE,"La solicitud expiró o ya fue atendida. El usuario debe crear una nueva solicitud.");}
            Instant expires=instant(requests.getFirst().get("Expires_At"));
            db.update("UPDATE users SET Password_Hash=:hash,Must_Change_Password=TRUE,Temporary_Password_Expires_At=(SELECT Expires_At FROM password_reset_requests WHERE Id_Request=:request),Auth_Version=Auth_Version+1,Password_Changed_At=UTC_TIMESTAMP(6) WHERE Id_User=:id",Map.of("hash",encoder.encode(password),"request",requestId,"id",userId));
            db.update("UPDATE password_reset_requests SET Reset_At=UTC_TIMESTAMP(6),Completed_By=:admin WHERE Id_Request=:request",Map.of("admin",admin,"request",requestId));user.put("Temporary_Expires",expires);
            audit(admin,userId,"PASSWORD_RESET");return user;});
        String token=randomToken();Instant expires=(Instant)result.get("Temporary_Expires");String email=Objects.toString(result.get("Email"),"").trim();String name=(Objects.toString(result.get("First_Name"),"")+" "+Objects.toString(result.get("Last_Name"),"")).trim();deliveries.put(token,new DeliverySecret(userId,requestId,admin,password,email,name,expires,new AtomicBoolean()));
        return Map.of("deliveryToken",token,"deliveryExpiresAt",expires,"canNotify",validEmail(email),"email",mask(email),"mustChangePassword",true);
    }

    public Map<String,Object> notifyUser(String token,Authentication auth){requireSuperAdmin(auth);DeliverySecret secret=deliveries.get(token);if(secret==null||!secret.expires().isAfter(Instant.now())||!secret.adminId().equals(auth.getName())){deliveries.remove(token);expirePending();throw new ResponseStatusException(HttpStatus.GONE,"La solicitud o la contraseña temporal expiró. El usuario debe crear una nueva solicitud.");}Integer valid=db.queryForObject("SELECT COUNT(*) FROM password_reset_requests pr JOIN users u ON u.Id_User=pr.Id_User WHERE pr.Id_Request=:request AND pr.Id_User=:user AND pr.Status='PENDING' AND pr.Reset_At IS NOT NULL AND pr.Notified_At IS NULL AND pr.Expires_At>UTC_TIMESTAMP(6) AND u.Must_Change_Password=TRUE AND u.Temporary_Password_Expires_At>UTC_TIMESTAMP(6)",Map.of("request",secret.requestId(),"user",secret.userId()),Integer.class);if(valid==null||valid==0){deliveries.remove(token);expirePending();throw new ResponseStatusException(HttpStatus.GONE,"La entrega ya no está vigente.");}if(!validEmail(secret.email()))throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"El usuario no tiene un correo válido.");if(!secret.sending().compareAndSet(false,true))throw new ResponseStatusException(HttpStatus.CONFLICT,"El envío ya está en curso.");
        boolean sent;try{sent=mail.sendTemporaryPassword(secret.email(),secret.name(),secret.password(),secret.expires());}finally{secret.sending().set(false);}if(!sent)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"La contraseña fue restablecida, pero no fue posible enviar el correo. Puedes reintentar mientras la solicitud y la contraseña temporal sigan vigentes.");
        deliveries.remove(token);if(secret.requestId()!=null&&!secret.requestId().isBlank())db.update("UPDATE password_reset_requests SET Notified_At=UTC_TIMESTAMP(6) WHERE Id_Request=:id AND Id_User=:user",Map.of("id",secret.requestId(),"user",secret.userId()));audit(auth.getName(),secret.userId(),"TEMPORARY_PASSWORD_SENT");return Map.of("sent",true);
    }

    public void reject(String requestId,Authentication auth){requireSuperAdmin(auth);expirePending();int n=db.update("UPDATE password_reset_requests SET Status='REJECTED',Completed_At=UTC_TIMESTAMP(6),Completed_By=:admin WHERE Id_Request=:id AND Status='PENDING' AND Reset_At IS NULL AND Expires_At>UTC_TIMESTAMP(6)",Map.of("admin",auth.getName(),"id",requestId));if(n==0)throw new ResponseStatusException(HttpStatus.CONFLICT,"La solicitud expiró o ya fue atendida.");}
    public void requireSuperAdmin(Authentication auth){Integer n=db.queryForObject("SELECT COUNT(*) FROM user_system_roles ur JOIN roles r ON r.Id_Role=ur.Id_Role AND r.Id_System=ur.Id_System JOIN systems s ON s.Id_System=r.Id_System JOIN user_system_access a ON a.Id_User=ur.Id_User AND a.Id_System=s.Id_System WHERE ur.Id_User=:user AND ur.Is_Active=TRUE AND r.Code='SUPER_ADMIN' AND r.Is_Active=TRUE AND s.Code='LICENSE_CONTROL' AND s.Is_Active=TRUE AND a.Is_Active=TRUE AND a.Status='ACTIVE'",Map.of("user",auth.getName()),Integer.class);if(n==null||n==0)throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Solo un Super Administrador puede realizar esta operación.");}
    private void audit(String actor,String entity,String action){db.update("INSERT INTO audit_events(Id_Audit_Event,Id_User,Action,Entity_Type,Entity_Id) VALUES(:id,:actor,:action,'users',:entity)",Map.of("id",UUID.randomUUID().toString(),"actor",actor,"action",action,"entity",entity));}
    private static String temporaryPassword(){String alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";List<Character> chars=new ArrayList<>();for(String group:List.of("ABCDEFGHJKLMNPQRSTUVWXYZ","abcdefghijkmnopqrstuvwxyz","23456789","!@#$%"))chars.add(group.charAt(RANDOM.nextInt(group.length())));while(chars.size()<18)chars.add(alphabet.charAt(RANDOM.nextInt(alphabet.length())));Collections.shuffle(chars,RANDOM);StringBuilder out=new StringBuilder();chars.forEach(out::append);return out.toString();}
    private static String randomToken(){byte[] b=new byte[32];RANDOM.nextBytes(b);return Base64.getUrlEncoder().withoutPadding().encodeToString(b);}
    private static boolean validEmail(String email){return email!=null&&email.matches("[^\\s@,;<>]+@[^\\s@,;<>]+\\.[^\\s@,;<>]+");}
    private static String mask(String email){if(!validEmail(email))return "";int at=email.indexOf('@');return email.substring(0,Math.min(2,at))+"***"+email.substring(at);}
    private void expirePending(){db.update("UPDATE password_reset_requests SET Status='EXPIRED' WHERE Status='PENDING' AND Expires_At<=UTC_TIMESTAMP(6)",Map.of());deliveries.entrySet().removeIf(entry->!entry.getValue().expires().isAfter(Instant.now()));}
    private static Instant instant(Object value){if(value instanceof java.sql.Timestamp timestamp)return timestamp.toLocalDateTime().toInstant(ZoneOffset.UTC);if(value instanceof java.time.LocalDateTime local)return local.toInstant(ZoneOffset.UTC);return Instant.parse(value.toString());}
}
