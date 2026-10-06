package com.etic.licensecontrol.licensing;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.web.server.ResponseStatusException;

@Service
public class DeviceLicensingService {
    private final NamedParameterJdbcTemplate db;
    private final DeviceCrypto crypto;
    private final TransactionTemplate tx;
    private final EntitlementService entitlements;
    public DeviceLicensingService(NamedParameterJdbcTemplate db,DeviceCrypto crypto,PlatformTransactionManager manager,EntitlementService entitlements) {
        this.entitlements=entitlements;this.db=db;this.crypto=crypto;this.tx=new TransactionTemplate(manager);
    }
    public record Enrollment(String system,String packageName,String code,String publicKey,String fingerprint,String signature,
        String manufacturer,String model,String androidVersion,String displayName,String appVersion) {}
    public record Proof(String licenseId,String challengeId,String signature) {}
    public record Activation(String entitlementId,Instant expiresAt) {}

    public List<Map<String,Object>> codes() {
        var rows=db.queryForList("SELECT e.Id_Enrollment,e.Id_Entitlement,e.Id_Device,d.Display_Name,c.Name Customer_Name,s.Name System_Name,e.Expires_At,e.Used_At,e.Revoked_At,e.Created_At FROM device_enrollment_codes e JOIN license_entitlements le ON le.Id_Entitlement=e.Id_Entitlement JOIN customers c ON c.Id_Customer=le.Id_Customer JOIN systems s ON s.Id_System=le.Id_System LEFT JOIN licensed_devices d ON d.Id_Device=e.Id_Device ORDER BY e.Created_At DESC LIMIT 100",Map.of());
        rows.forEach(row->row.replaceAll((key,value)->value instanceof Timestamp t?t.toLocalDateTime().toString()+"Z":value instanceof LocalDateTime time?time.toString()+"Z":value));
        return rows;
    }
    public Map<String,Object> generate(Activation input,String actor) {
        return tx.execute(status->{
            var mandatory=db.queryForList("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='device_enrollment_codes' AND IS_NULLABLE='NO' AND COLUMN_DEFAULT IS NULL AND EXTRA NOT LIKE '%auto_increment%'",Map.of(),String.class);
            mandatory.removeAll(Set.of("Id_Enrollment","Id_Entitlement","Code_Hash","Expires_At","Created_At","Created_By"));
            if(!mandatory.isEmpty()){
                org.slf4j.LoggerFactory.getLogger(DeviceLicensingService.class).error("Enrollment schema incompatible; required columns without values: {}",mandatory);
                throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"ENROLLMENT_SCHEMA_NOT_READY: La base conectada necesita actualizar su estructura de códigos de activación; no permite generarlos antes de vincular dispositivos.");
            }
            var license=entitlements.usable(input.entitlementId());
            required(Objects.toString(license.get("Package_Name"),""),255);
            Instant now=Instant.now();
            if(input.expiresAt()==null||!input.expiresAt().isAfter(now)||input.expiresAt().isAfter(now.plusSeconds(604800)))throw new IllegalArgumentException("El código debe vencer dentro de los próximos 7 días");
            String code=crypto.randomToken(),id=UUID.randomUUID().toString();
            var p=new MapSqlParameterSource().addValue("entitlement",input.entitlementId()).addValue("actor",actor)
                .addValue("id",id).addValue("hash",DeviceCrypto.hash(license.get("Id_System")+"|"+code)).addValue("expires",LocalDateTime.ofInstant(input.expiresAt(),ZoneOffset.UTC));
            db.update("INSERT INTO device_enrollment_codes(Id_Enrollment,Id_Device,Id_Entitlement,Code_Hash,Expires_At,Created_At,Created_By) VALUES(:id,NULL,:entitlement,:hash,:expires,UTC_TIMESTAMP(),:actor)",p);
            return Map.of("id",id,"code",code,"expiresAt",input.expiresAt(),"system",license.get("Code"),"packageName",license.get("Package_Name"));
        });
    }
    public Map<String,Object> enroll(Enrollment input) {
        return audited("DEVICE_ENROLLED",()->tx.execute(status->{
            required(input.system(),80); required(input.packageName(),255); required(input.code(),128);
            var systems=db.queryForList("SELECT s.Id_System FROM systems s JOIN system_licensing sl ON sl.Id_System=s.Id_System WHERE s.Code=:code AND s.Package_Name=:package AND s.Is_Active=TRUE AND s.Status='ACTIVE' AND s.System_Type='ANDROID' AND sl.Is_Active=TRUE AND sl.Licensing_Mode='DEVICE_ONLY'",Map.of("code",input.system(),"package",input.packageName()));
            if(systems.size()!=1)throw denied("Sistema no autorizado para activación");
            String system=systems.getFirst().get("Id_System").toString();
            var codes=db.queryForList("SELECT * FROM device_enrollment_codes WHERE Code_Hash=:hash AND Used_At IS NULL AND Revoked_At IS NULL AND Expires_At>UTC_TIMESTAMP()",Map.of("hash",DeviceCrypto.hash(system+"|"+input.code())));
            if(codes.isEmpty())throw denied("Código de activación inválido, vencido o usado");
            var code=codes.getFirst();
            if(code.get("Id_Entitlement")==null)throw denied("Código de activación incompatible");
            String entitlementId=code.get("Id_Entitlement").toString();
            var entitlement=entitlements.usable(entitlementId);
            if(db.queryForList("SELECT Id_Enrollment FROM device_enrollment_codes WHERE Id_Enrollment=:id AND Used_At IS NULL AND Revoked_At IS NULL AND Expires_At>UTC_TIMESTAMP() FOR UPDATE",Map.of("id",code.get("Id_Enrollment"))).isEmpty())throw denied("Código de activación inválido, vencido o usado");
            if(!system.equals(entitlement.get("Id_System")))throw denied("Código de activación inválido");
            int occupied=db.queryForList("SELECT Id_License FROM licenses WHERE Id_Entitlement=:id AND Status IN ('ACTIVE','SUSPENDED') FOR UPDATE",Map.of("id",entitlementId)).size();
            if(occupied>=((Number)entitlement.get("Seat_Count")).intValue())throw EntitlementService.denied("NO_SEATS_AVAILABLE","No hay dispositivos disponibles en esta licencia");
            String device=UUID.randomUUID().toString(),licenseId=UUID.randomUUID().toString();
            var key=crypto.publicKey(input.publicKey()); String fingerprint=DeviceCrypto.hash(key.getEncoded());
            if(!fingerprint.equals(input.fingerprint()))throw denied("Identidad del dispositivo inválida");
            String transcript="LC-ENROLL-V1\n"+input.system()+"\n"+input.packageName()+"\n"+input.code()+"\n"+fingerprint;
            if(!crypto.verify(input.publicKey(),transcript.getBytes(StandardCharsets.UTF_8),input.signature()))throw denied("Identidad del dispositivo inválida");
            optional(input.manufacturer(),100);optional(input.model(),100);optional(input.androidVersion(),50);optional(input.displayName(),150);optional(input.appVersion(),80);
            var p=new MapSqlParameterSource().addValue("device",device).addValue("key",Base64.getEncoder().encodeToString(key.getEncoded())).addValue("fingerprint",fingerprint)
                .addValue("package",input.packageName()).addValue("manufacturer",input.manufacturer()).addValue("model",input.model()).addValue("android",input.androidVersion()).addValue("code",code.get("Id_Enrollment")).addValue("name",input.displayName()).addValue("version",input.appVersion());
            db.update("INSERT INTO licensed_devices(Id_Device,Origin,Public_Key,Public_Key_Fingerprint,Public_Key_Algorithm,Package_Name,Manufacturer,Model,Android_Version,Display_Name,App_Version,Status,Registered_At,Enrolled_At) VALUES(:device,'AUTO',:key,:fingerprint,'EC',:package,:manufacturer,:model,:android,:name,:version,'ACTIVE',UTC_TIMESTAMP(),UTC_TIMESTAMP())",p);
            Instant until=EntitlementService.expiry(entitlement);
            p.addValue("license",licenseId).addValue("entitlement",entitlementId).addValue("system",system)
                .addValue("start",LocalDate.now(ZoneOffset.UTC)).addValue("end",until==null?LocalDate.of(9999,12,31):until.atOffset(ZoneOffset.UTC).toLocalDate());
            db.update("INSERT INTO licenses(Id_License,Id_Entitlement,Id_System,Id_Device,Valid_From,Valid_Until,Status,Created_At) VALUES(:license,:entitlement,:system,:device,:start,:end,'ACTIVE',UTC_TIMESTAMP())",p);
            if(db.update("UPDATE device_enrollment_codes SET Used_At=UTC_TIMESTAMP(),Id_Device=:device WHERE Id_Enrollment=:code AND Used_At IS NULL AND Revoked_At IS NULL AND Expires_At>UTC_TIMESTAMP()",p)!=1)throw denied("Código de activación inválido, vencido o usado");
            entitlement.put("Public_Key_Fingerprint",fingerprint);
            return credential(entitlement,device,licenseId);
        }));
    }
    public Map<String,Object> challenge(String device,String licenseId) {
        return audited("DEVICE_CHALLENGE",()->tx.execute(status->{
            var license=license(licenseId,device,false);
            int recent=db.queryForObject("SELECT COUNT(*) FROM device_challenges WHERE Id_Device=:device AND Created_At>DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 MINUTE)",Map.of("device",device),Integer.class);
            if(recent>=10)throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"Espera un minuto antes de solicitar otro challenge");
            // El contexto forma parte del mensaje firmado y evita trasladar una prueba a otra licencia.
            String nonce=Base64.getUrlEncoder().withoutPadding().encodeToString((licenseId+"\n"+crypto.randomToken()).getBytes(StandardCharsets.UTF_8));
            String id=UUID.randomUUID().toString(); Instant expires=Instant.now().plusSeconds(120);
            db.update("INSERT INTO device_challenges(Id_Challenge,Id_Device,Nonce_Value,Nonce_Hash,Expires_At,Created_At) VALUES(:id,:device,:nonce,:hash,:expires,UTC_TIMESTAMP())",Map.of("id",id,"device",device,"nonce",nonce,"hash",DeviceCrypto.hash(nonce),"expires",LocalDateTime.ofInstant(expires,ZoneOffset.UTC)));
            return Map.of("challengeId",id,"deviceId",device,"licenseId",licenseId,"nonce",nonce,"expiresAt",expires);
        }));
    }
    public Map<String,Object> validate(String device,Proof proof,String action) {
        return audited("DEVICE_"+action.toUpperCase(Locale.ROOT),()->tx.execute(status->{
            var license=license(proof.licenseId(),device,false);
            required(proof.challengeId(),38);
            var rows=db.queryForList("SELECT Nonce_Value FROM device_challenges WHERE Id_Challenge=:id AND Id_Device=:device AND Used_At IS NULL AND Expires_At>UTC_TIMESTAMP() FOR UPDATE",Map.of("id",proof.challengeId(),"device",device));
            if(rows.isEmpty())throw denied("Credencial requiere renovación: challenge inválido, vencido o usado");
            String nonce=rows.getFirst().get("Nonce_Value").toString(); byte[] message=Base64.getUrlDecoder().decode(nonce);
            if(!new String(message,StandardCharsets.UTF_8).startsWith(proof.licenseId()+"\n")||!crypto.verify(license.get("Public_Key").toString(),message,proof.signature()))throw denied("Dispositivo no autorizado");
            var response=credential(license,device,proof.licenseId());
            if(db.update("UPDATE device_challenges SET Used_At=UTC_TIMESTAMP(),Credential_Issued_At=UTC_TIMESTAMP() WHERE Id_Challenge=:id AND Used_At IS NULL AND Expires_At>UTC_TIMESTAMP()",Map.of("id",proof.challengeId()))!=1)throw denied("Credencial requiere renovación");
            db.update("UPDATE licensed_devices SET Last_Validation_At=UTC_TIMESTAMP() WHERE Id_Device=:id",Map.of("id",device));
            return response;
        }));
    }
    private Map<String,Object> credential(Map<String,Object> license,String device,String licenseId) {
        int days=((Number)license.get("Offline_Validity_Days")).intValue();
        if(days<1||days>30)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Configura una ventana offline entre 1 y 30 días para este sistema Android.");
        Instant now=Instant.now(),expiry=EntitlementService.expiry(license);
        Instant offline=now.plusSeconds(days*86400L);if(expiry!=null&&offline.isAfter(expiry))offline=expiry;
        Map<String,Object> claims=new LinkedHashMap<>();
        claims.put("licenseId",licenseId);claims.put("entitlementId",license.get("Id_Entitlement"));claims.put("systemId",license.get("Id_System"));
        claims.put("deviceId",device);claims.put("deviceFingerprint",license.get("Public_Key_Fingerprint"));claims.put("packageName",license.get("Package_Name"));
        claims.put("issuedAt",now.getEpochSecond());claims.put("expiresAt",expiry==null?null:expiry.getEpochSecond());claims.put("offlineUntil",offline.getEpochSecond());claims.put("status","ACTIVE");claims.put("formatVersion",2);
        String signed=crypto.issue(claims);
        var response=new LinkedHashMap<>(claims);response.put("allowed",true);response.put("credential",signed);response.put("serverTime",now.getEpochSecond());return response;
    }
    private Map<String,Object> license(String id,String device,boolean enrollment) {
        required(id,38);
        var owners=db.queryForList("SELECT Id_Entitlement FROM licenses WHERE Id_License=:id",Map.of("id",id));
        if(owners.isEmpty()||owners.getFirst().get("Id_Entitlement")==null)throw EntitlementService.denied("LICENSE_REVOKED","Licencia comercial no disponible");
        var entitlement=entitlements.usable(owners.getFirst().get("Id_Entitlement").toString());
        var rows=db.queryForList("SELECT l.*,s.Code,s.Package_Name,s.System_Type,s.Is_Active System_Active,s.Status System_Status,sl.Offline_Validity_Days,sl.Is_Active Licensing_Active,sl.Licensing_Mode,d.Is_Active Device_Active,d.Status Device_Status,d.Public_Key,d.Public_Key_Fingerprint,d.Package_Name Device_Package FROM licenses l JOIN systems s ON s.Id_System=l.Id_System JOIN system_licensing sl ON sl.Id_System=s.Id_System JOIN licensed_devices d ON d.Id_Device=l.Id_Device WHERE l.Id_License=:id FOR UPDATE",Map.of("id",id));
        if(rows.isEmpty())throw denied("Dispositivo no autorizado");
        var l=rows.getFirst();
        if(device!=null&&!device.equals(l.get("Id_Device")))throw denied("Dispositivo no autorizado");
        if(!Objects.equals(l.get("Id_System"),entitlement.get("Id_System")))throw denied("Sistema no autorizado");
        if("REVOKED".equals(l.get("Device_Status")))throw EntitlementService.denied("DEVICE_REVOKED","Dispositivo revocado");
        if(!enabled(l.get("Is_Active"))||"REVOKED".equals(l.get("Status")))throw EntitlementService.denied("LICENSE_REVOKED","Licencia revocada");
        if("SUSPENDED".equals(l.get("Status")))throw EntitlementService.denied("LICENSE_SUSPENDED","Licencia suspendida");
        if("EXPIRED".equals(l.get("Status")))throw EntitlementService.denied("LICENSE_EXPIRED","Licencia vencida");
        if(!"ACTIVE".equals(l.get("Status")))throw denied("Licencia aún no vigente");
        if(!"ANDROID".equals(l.get("System_Type"))||!enabled(l.get("System_Active"))||!"ACTIVE".equals(l.get("System_Status"))||!enabled(l.get("Licensing_Active"))||!"DEVICE_ONLY".equals(l.get("Licensing_Mode"))||l.get("Id_Usuario")!=null)throw denied("Sistema no autorizado para licenciamiento de dispositivo");
        required(Objects.toString(l.get("Package_Name"),""),255);
        if(!enabled(l.get("Device_Active"))||!(enrollment?Set.of("PENDING","ACTIVE","ENROLLED"):Set.of("ACTIVE")).contains(l.get("Device_Status")))throw EntitlementService.denied("DEVICE_REVOKED","Dispositivo no autorizado");
        if(!enrollment&&(l.get("Public_Key")==null||!Objects.equals(l.get("Package_Name"),l.get("Device_Package"))))throw denied("Dispositivo no autorizado");
        l.put("Expires_At",entitlement.get("Expires_At"));return l;
    }
    // Fuera de la transacción operativa: los rechazos no se pierden por rollback.
    private Map<String,Object> audited(String type,java.util.function.Supplier<Map<String,Object>> operation) {
        try { var result=operation.get(); event(type,"SUCCESS",result,null); return result; }
        catch(ResponseStatusException ex) { event(type,"DENIED",Map.of(),ex.getReason());throw ex; }
        catch(IllegalArgumentException ex) { event(type,"DENIED",Map.of(),"Solicitud de dispositivo inválida");throw ex; }
        catch(RuntimeException ex) { event(type,"ERROR",Map.of(),"No fue posible completar la validación");throw ex; }
    }
    private void event(String type,String result,Map<String,Object> data,String reason) {
        db.update("INSERT INTO license_validation_events(Id_Event,Id_Device,Id_License,Event_Type,Result,Reason,Created_At) VALUES(:id,:device,:license,:type,:result,:reason,UTC_TIMESTAMP())",new MapSqlParameterSource().addValue("id",UUID.randomUUID().toString()).addValue("device",data.get("deviceId")).addValue("license",data.get("licenseId")).addValue("type",type).addValue("result",result).addValue("reason",reason));
    }
    private static LocalDate date(Object value) { return LocalDate.parse(value.toString()); }
    private static boolean enabled(Object value) { return Boolean.TRUE.equals(value)||value instanceof Number n&&n.intValue()!=0; }
    private static void required(String value,int max) { if(value==null||value.isBlank()||value.length()>max)throw new IllegalArgumentException("Faltan datos válidos para completar la operación"); }
    private static void optional(String value,int max) { if(value!=null&&value.length()>max)throw new IllegalArgumentException("Los datos del dispositivo exceden la longitud permitida"); }
    private static ResponseStatusException denied(String message) { return new ResponseStatusException(HttpStatus.FORBIDDEN,message); }
}
