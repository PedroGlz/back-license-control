package com.etic.licensecontrol.licensing;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.*;
import java.util.*;
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
    private final LicenseService licenses;
    public DeviceLicensingService(NamedParameterJdbcTemplate db,DeviceCrypto crypto,PlatformTransactionManager manager,LicenseService licenses) {
        this.licenses=licenses;this.db=db;this.crypto=crypto;this.tx=new TransactionTemplate(manager);
    }
    public record Enrollment(String system,String packageName,String code,String publicKey,String fingerprint,String signature,
        String manufacturer,String model,String androidVersion,String displayName,String appVersion) {}
    public record Proof(String licenseId,String challengeId,String signature) {}
    public record Activation(String licenseId,Integer quantity,Instant expiresAt) {}

    public List<Map<String,Object>> codes() {
        var rows=db.queryForList("SELECT e.Id_Enrollment,e.Id_License,e.Id_Device,d.Display_Name,c.Name Customer_Name,s.Name System_Name,l.Status License_Status,l.Expires_At License_Expires_At,e.Expires_At,e.Used_At,e.Created_At FROM device_enrollment_codes e JOIN licenses l ON l.Id_License=e.Id_License JOIN customers c ON c.Id_Customer=l.Id_Customer JOIN systems s ON s.Id_System=l.Id_System LEFT JOIN licensed_devices d ON d.Id_Device=e.Id_Device ORDER BY e.Created_At DESC LIMIT 100",Map.of());
        rows.forEach(row->row.replaceAll((key,value)->value instanceof Timestamp t?t.toLocalDateTime().toString()+"Z":value instanceof LocalDateTime time?time.toString()+"Z":value));
        return rows;
    }
    public Map<String,Object> generate(Activation input,String actor) {
        return tx.execute(status->{
            var license=licenses.usable(input.licenseId());
            deviceOnly(license);
            if(input.quantity()==null||input.quantity()<1)throw new IllegalArgumentException("La cantidad debe ser un entero mayor o igual a 1");
            int available=Math.max(0,((Number)license.get("Seat_Count")).intValue()-licenses.used(input.licenseId()));
            if(input.quantity()>available)throw new ResponseStatusException(HttpStatus.CONFLICT,"NO_SEATS_AVAILABLE: La licencia tiene "+available+" dispositivos disponibles.");
            Instant now=Instant.now();
            if(input.expiresAt()==null||!input.expiresAt().isAfter(now)||input.expiresAt().isAfter(now.plusSeconds(604800)))throw new IllegalArgumentException("El código debe vencer dentro de los próximos 7 días");
            Set<String> uniqueCodes=new LinkedHashSet<>();
            while(uniqueCodes.size()<input.quantity())uniqueCodes.add(crypto.randomToken());
            for(String code:uniqueCodes) {
                var p=new MapSqlParameterSource().addValue("license",input.licenseId()).addValue("actor",actor)
                    .addValue("id",UUID.randomUUID().toString()).addValue("hash",DeviceCrypto.hash(code)).addValue("expires",LocalDateTime.ofInstant(input.expiresAt(),ZoneOffset.UTC));
                db.update("INSERT INTO device_enrollment_codes(Id_Enrollment,Id_License,Id_Device,Code_Hash,Expires_At,Created_By) VALUES(:id,:license,NULL,:hash,:expires,:actor)",p);
            }
            var codes=List.copyOf(uniqueCodes);
            return Map.of("codes",codes,"code",codes.getFirst(),"expiresAt",input.expiresAt(),"system",license.get("Code"),"packageName",license.get("Package_Name"));
        });
    }
    public Map<String,Object> enroll(Enrollment input) {
        return audited("DEVICE_ENROLLED",()->tx.execute(status->{
            required(input.system(),80);required(input.packageName(),255);required(input.code(),128);
            var codes=db.queryForList("SELECT Id_Enrollment,Id_License FROM device_enrollment_codes WHERE Code_Hash=:hash",Map.of("hash",DeviceCrypto.hash(input.code())));
            if(codes.isEmpty())throw denied("ENROLLMENT_CODE_INVALID","Código de activación inválido");
            String licenseId=codes.getFirst().get("Id_License").toString();
            var license=licenses.usable(licenseId);
            deviceOnly(license);
            if(!input.system().equals(license.get("Code"))||!input.packageName().equals(license.get("Package_Name")))throw denied("ENROLLMENT_CODE_INVALID","El código no corresponde al sistema");
            var code=db.queryForList("SELECT * FROM device_enrollment_codes WHERE Id_Enrollment=:id FOR UPDATE",Map.of("id",codes.getFirst().get("Id_Enrollment"))).getFirst();
            if(code.get("Used_At")!=null)throw denied("ENROLLMENT_CODE_USED","El código ya fue utilizado");
            if(!instant(code.get("Expires_At")).isAfter(Instant.now()))throw denied("ENROLLMENT_CODE_EXPIRED","El código ha vencido");
            if(licenses.used(licenseId)>=((Number)license.get("Seat_Count")).intValue())throw denied("NO_SEATS_AVAILABLE","No hay dispositivos disponibles en esta licencia");
            var key=crypto.publicKey(input.publicKey());String fingerprint=DeviceCrypto.hash(key.getEncoded());
            if(!fingerprint.equals(input.fingerprint()))throw denied("ACCESS_DENIED","Identidad del dispositivo inválida");
            String transcript="LC-ENROLL-V1\n"+input.system()+"\n"+input.packageName()+"\n"+input.code()+"\n"+fingerprint;
            if(!crypto.verify(input.publicKey(),transcript.getBytes(StandardCharsets.UTF_8),input.signature()))throw denied("ACCESS_DENIED","Identidad del dispositivo inválida");
            optional(input.manufacturer(),120);optional(input.model(),120);optional(input.androidVersion(),80);optional(input.displayName(),200);optional(input.appVersion(),80);
            String device;
            var existing=db.queryForList("SELECT Id_Device,Status,Is_Active FROM licensed_devices WHERE Fingerprint=:fingerprint FOR UPDATE",Map.of("fingerprint",fingerprint));
            if(existing.isEmpty()){
                device=UUID.randomUUID().toString();
                var p=new MapSqlParameterSource().addValue("device",device).addValue("key",Base64.getEncoder().encodeToString(key.getEncoded())).addValue("fingerprint",fingerprint)
                    .addValue("manufacturer",input.manufacturer()).addValue("model",input.model()).addValue("android",input.androidVersion()).addValue("name",input.displayName()).addValue("version",input.appVersion());
                db.update("INSERT INTO licensed_devices(Id_Device,Public_Key,Fingerprint,Manufacturer,Model,Android_Version,Display_Name,App_Version) VALUES(:device,:key,:fingerprint,:manufacturer,:model,:android,:name,:version)",p);
            }else{
                var found=existing.getFirst();
                if(!enabled(found.get("Is_Active"))||!"ACTIVE".equals(found.get("Status")))throw denied("DEVICE_REVOKED","Dispositivo no autorizado");
                device=found.get("Id_Device").toString();
            }
            var p=new MapSqlParameterSource().addValue("device",device).addValue("license",licenseId).addValue("id",UUID.randomUUID().toString()).addValue("code",code.get("Id_Enrollment"));
            if(!db.queryForList("SELECT Id_License_Device FROM license_devices WHERE Id_License=:license AND Id_Device=:device FOR UPDATE",p).isEmpty())throw denied("ENROLLMENT_CODE_INVALID","El dispositivo ya está vinculado a esta licencia");
            db.update("INSERT INTO license_devices(Id_License_Device,Id_License,Id_Device,Status) VALUES(:id,:license,:device,'ACTIVE')",p);
            if(db.update("UPDATE device_enrollment_codes SET Used_At=UTC_TIMESTAMP(6),Id_Device=:device WHERE Id_Enrollment=:code AND Used_At IS NULL AND Expires_At>UTC_TIMESTAMP(6)",p)!=1)throw denied("ENROLLMENT_CODE_EXPIRED","El código ha vencido");
            license.put("Fingerprint",fingerprint);
            return credential(license,device,licenseId);
        }));
    }
    public Map<String,Object> challenge(String device,String licenseId) {
        return audited("DEVICE_CHALLENGE",()->tx.execute(status->{
            license(licenseId,device);
            int recent=db.queryForObject("SELECT COUNT(*) FROM device_challenges WHERE Id_Device=:device AND Created_At>DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 MINUTE)",Map.of("device",device),Integer.class);
            if(recent>=10)throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"Espera un minuto antes de solicitar otro challenge");
            String nonce=Base64.getUrlEncoder().withoutPadding().encodeToString((licenseId+"\n"+crypto.randomToken()).getBytes(StandardCharsets.UTF_8));
            String id=UUID.randomUUID().toString();Instant expires=Instant.now().plusSeconds(120);
            db.update("INSERT INTO device_challenges(Id_Challenge,Id_Device,Nonce,Expires_At) VALUES(:id,:device,:nonce,:expires)",Map.of("id",id,"device",device,"nonce",nonce,"expires",LocalDateTime.ofInstant(expires,ZoneOffset.UTC)));
            return Map.of("challengeId",id,"deviceId",device,"licenseId",licenseId,"nonce",nonce,"expiresAt",expires);
        }));
    }
    public Map<String,Object> validate(String device,Proof proof,String action) {
        return audited("DEVICE_"+action.toUpperCase(Locale.ROOT),()->tx.execute(status->{
            var license=license(proof.licenseId(),device);required(proof.challengeId(),36);
            var rows=db.queryForList("SELECT Nonce,Used_At,Expires_At FROM device_challenges WHERE Id_Challenge=:id AND Id_Device=:device FOR UPDATE",Map.of("id",proof.challengeId(),"device",device));
            if(rows.isEmpty()||rows.getFirst().get("Used_At")!=null)throw denied("CHALLENGE_INVALID","Challenge inválido o utilizado");
            var challenge=rows.getFirst();
            if(!instant(challenge.get("Expires_At")).isAfter(Instant.now()))throw denied("CHALLENGE_EXPIRED","Challenge vencido");
            byte[] message=Base64.getUrlDecoder().decode(challenge.get("Nonce").toString());
            if(!new String(message,StandardCharsets.UTF_8).startsWith(proof.licenseId()+"\n")||!crypto.verify(license.get("Public_Key").toString(),message,proof.signature()))throw denied("CHALLENGE_INVALID","Prueba del dispositivo inválida");
            var response=credential(license,device,proof.licenseId());
            if(db.update("UPDATE device_challenges SET Used_At=UTC_TIMESTAMP(6) WHERE Id_Challenge=:id AND Used_At IS NULL AND Expires_At>UTC_TIMESTAMP(6)",Map.of("id",proof.challengeId()))!=1)throw denied("CHALLENGE_EXPIRED","Challenge vencido");
            db.update("UPDATE licensed_devices SET Last_Validation_At=UTC_TIMESTAMP(6),Modified_At=UTC_TIMESTAMP(6) WHERE Id_Device=:id",Map.of("id",device));
            return response;
        }));
    }
    private Map<String,Object> credential(Map<String,Object> license,String device,String licenseId) {
        int days=((Number)license.get("Offline_Validity_Days")).intValue();
        if(days<1||days>365)throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Ventana offline inválida");
        Instant now=Instant.now(),expiry=LicenseService.expiry(license);
        Instant offline=now.plusSeconds(days*86400L);if(expiry!=null&&offline.isAfter(expiry))offline=expiry;
        Map<String,Object> claims=new LinkedHashMap<>();
        claims.put("licenseId",licenseId);claims.put("systemId",license.get("Id_System"));
        claims.put("deviceId",device);claims.put("fingerprint",license.get("Fingerprint"));claims.put("packageName",license.get("Package_Name"));
        claims.put("issuedAt",now.getEpochSecond());claims.put("expiresAt",expiry==null?null:expiry.getEpochSecond());claims.put("offlineUntil",offline.getEpochSecond());claims.put("status","ACTIVE");claims.put("formatVersion",3);
        String signed=crypto.issue(claims);
        var response=new LinkedHashMap<>(claims);response.put("allowed",true);response.put("credential",signed);response.put("serverTime",now.getEpochSecond());return response;
    }
    private Map<String,Object> license(String id,String device) {
        required(id,36);required(device,36);
        var license=licenses.usable(id);
        var rows=db.queryForList("SELECT ld.Status Link_Status,d.Is_Active Device_Active,d.Status Device_Status,d.Public_Key,d.Fingerprint FROM license_devices ld JOIN licensed_devices d ON d.Id_Device=ld.Id_Device WHERE ld.Id_License=:id AND ld.Id_Device=:device FOR UPDATE",Map.of("id",id,"device",device));
        if(rows.isEmpty())throw denied("DEVICE_REVOKED","Dispositivo no vinculado");
        var relation=rows.getFirst();
        if(!enabled(relation.get("Device_Active"))||!"ACTIVE".equals(relation.get("Device_Status"))||!"ACTIVE".equals(relation.get("Link_Status")))throw denied("DEVICE_REVOKED","Dispositivo no autorizado");
        license.putAll(relation);return license;
    }
    private static void deviceOnly(Map<String,Object> license) {
        if(!"DEVICE_ONLY".equals(license.get("Licensing_Mode")))throw denied("ACCESS_DENIED","Esta operación requiere una licencia DEVICE_ONLY");
    }
    private Map<String,Object> audited(String type,java.util.function.Supplier<Map<String,Object>> operation) {
        try { var result=operation.get();event(type,true,result,null);return result; }
        catch(ResponseStatusException ex) { String reason=Objects.toString(ex.getReason(),"ACCESS_DENIED");event(type,false,Map.of(),reason.contains(":")?reason.substring(0,reason.indexOf(':')):"ACCESS_DENIED");throw ex; }
        catch(IllegalArgumentException ex) { event(type,false,Map.of(),"INVALID_REQUEST");throw ex; }
        catch(RuntimeException ex) { event(type,false,Map.of(),"VALIDATION_ERROR");throw ex; }
    }
    private void event(String type,boolean success,Map<String,Object> data,String code) {
        db.update("INSERT INTO license_validation_events(Id_Validation_Event,Id_Device,Id_License,Id_System,Event_Type,Success,Failure_Code) VALUES(:id,:device,:license,:system,:type,:success,:code)",new MapSqlParameterSource().addValue("id",UUID.randomUUID().toString()).addValue("device",data.get("deviceId")).addValue("license",data.get("licenseId")).addValue("system",data.get("systemId")).addValue("type",type).addValue("success",success).addValue("code",code));
    }
    private static Instant instant(Object value) { return (value instanceof Timestamp t?t.toLocalDateTime():(LocalDateTime)value).toInstant(ZoneOffset.UTC); }
    private static boolean enabled(Object value) { return Boolean.TRUE.equals(value)||value instanceof Number n&&n.intValue()!=0; }
    private static void required(String value,int max) { if(value==null||value.isBlank()||value.length()>max)throw new IllegalArgumentException("Faltan datos válidos para completar la operación"); }
    private static void optional(String value,int max) { if(value!=null&&value.length()>max)throw new IllegalArgumentException("Los datos del dispositivo exceden la longitud permitida"); }
    private static ResponseStatusException denied(String code,String message) { return LicenseService.denied(code,message); }
}
