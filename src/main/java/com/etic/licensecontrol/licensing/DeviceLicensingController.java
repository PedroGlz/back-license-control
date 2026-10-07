package com.etic.licensecontrol.licensing;

import java.util.*;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
public class DeviceLicensingController {
    private final DeviceLicensingService service;
    private final MailService mail;
    private final org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate db;
    public DeviceLicensingController(DeviceLicensingService service,MailService mail,org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate db) { this.service=service;this.mail=mail;this.db=db; }
    public record GenerateRequest(String licenseId,java.time.Instant expiresAt,boolean sendEmail) {}
    @PostMapping("/api/mobile/device/enroll")
    ResponseEntity<?> enroll(@RequestBody DeviceLicensingService.Enrollment body) { return response(service.enroll(body)); }
    @PostMapping("/api/mobile/device/{deviceId}/challenge")
    ResponseEntity<?> challenge(@PathVariable String deviceId,@RequestBody DeviceLicensingService.Proof body) { return response(service.challenge(deviceId,body.licenseId())); }
    @PostMapping("/api/mobile/device/{deviceId}/{action:verify|validate|refresh}")
    ResponseEntity<?> verify(@PathVariable String deviceId,@PathVariable String action,@RequestBody DeviceLicensingService.Proof body) { return response(service.validate(deviceId,body,action)); }
    @GetMapping("/api/admin/enrollment-codes")
    ResponseEntity<?> codes() { return response(service.codes()); }
    @PostMapping("/api/admin/enrollment-codes")
    ResponseEntity<?> generate(@RequestBody GenerateRequest body,Authentication auth) {
        if(body.licenseId()==null)throw new IllegalArgumentException("Selecciona una licencia");
        var owners=db.queryForList("SELECT c.Id_Customer,c.Name Customer_Name,c.Email,s.Name System_Name,e.Term_Type,e.Seat_Count FROM licenses e JOIN customers c ON c.Id_Customer=e.Id_Customer JOIN systems s ON s.Id_System=e.Id_System WHERE e.Id_License=:id AND e.Licensing_Mode='DEVICE_ONLY'",Map.of("id",body.licenseId()));
        if(owners.isEmpty())throw new IllegalArgumentException("Licencia no encontrada");
        var owner=owners.getFirst();String email=Objects.toString(owner.get("Email"),"").trim();
        if(body.sendEmail()&&email.isBlank())throw new IllegalArgumentException("El cliente no tiene un correo configurado.");
        if(body.sendEmail()&&!email.matches("[^\\s@,;<>]+@[^\\s@,;<>]+\\.[^\\s@,;<>]+"))throw new IllegalArgumentException("El correo configurado del cliente no es válido.");
        // generate retorna después del COMMIT de su TransactionTemplate. SMTP nunca pertenece a esa transacción.
        var generated=service.generate(new DeviceLicensingService.Activation(body.licenseId(),body.expiresAt()),auth.getName());
        var codes=List.of(generated.get("code").toString());boolean sent=false;
        if(body.sendEmail()) {
            sent=mail.sendActivationCodes(email,owner.get("Customer_Name").toString(),owner.get("System_Name").toString(),codes,body.expiresAt(),owner.get("Term_Type").toString(),((Number)owner.get("Seat_Count")).intValue());
            String action=sent?"EMAIL_SENT":"EMAIL_FAILED";
            var metadata=Map.of("customer",owner.get("Id_Customer"),"license",body.licenseId(),"quantity",codes.size(),"email",email);
            try {
                db.update("INSERT INTO audit_events(Id_Audit_Event,Action,Entity_Type,Entity_Id,New_Value) VALUES(:id,:action,'activation_code_email',:license,:metadata)",Map.of("id",UUID.randomUUID().toString(),"action",action,"license",body.licenseId(),"metadata",tools.jackson.databind.json.JsonMapper.builder().build().writeValueAsString(metadata)));
            } catch(Exception ex) {
                // Aun si falla la auditoría, devolver los códigos ya confirmados; sin payload ni excepción SMTP.
                org.slf4j.LoggerFactory.getLogger(DeviceLicensingController.class).warn("Auditoría de correo no persistida: customer={}, license={}, quantity={}, email={}, date={}, action={}",owner.get("Id_Customer"),body.licenseId(),codes.size(),email,java.time.Instant.now(),action);
            }
        }
        Map<String,Object> result=new LinkedHashMap<>();result.put("codes",codes);result.put("code",codes.getFirst());result.put("expiresAt",generated.get("expiresAt"));result.put("system",owner.get("System_Name"));
        result.put("codesGenerated",true);result.put("emailRequested",body.sendEmail());result.put("emailSent",sent);result.put("email",body.sendEmail()?email:null);
        result.put("message",!body.sendEmail()?"Códigos generados correctamente.":sent?"Códigos generados y enviados correctamente a "+email+".":"Los códigos fueron generados correctamente, pero no fue posible enviar el correo.");
        return response(result);
    }
    private static ResponseEntity<?> response(Object value) { return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(value); }
    @ExceptionHandler(org.springframework.web.server.ResponseStatusException.class)
    ResponseEntity<?> denied(org.springframework.web.server.ResponseStatusException ex) {
        if(ex.getStatusCode().is5xxServerError())org.slf4j.LoggerFactory.getLogger(DeviceLicensingController.class).error("No fue posible emitir la credencial offline",ex);
        String reason=Objects.toString(ex.getReason(),"Operación no disponible");
        int separator=reason.indexOf(':');String code=separator>0?reason.substring(0,separator):"ACCESS_DENIED";
        if(!Set.of("LICENSE_SUSPENDED","LICENSE_REVOKED","LICENSE_EXPIRED","DEVICE_REVOKED","NO_SEATS_AVAILABLE","LICENSE_NOT_FOUND","ENROLLMENT_CODE_INVALID","ENROLLMENT_CODE_EXPIRED","ENROLLMENT_CODE_USED","CHALLENGE_INVALID","CHALLENGE_EXPIRED").contains(code))code=ex.getStatusCode().is5xxServerError()?"CREDENTIAL_UNAVAILABLE":"ACCESS_DENIED";
        return ResponseEntity.status(ex.getStatusCode()).cacheControl(CacheControl.noStore()).body(Map.of("allowed",false,"code",code,"message",reason));
    }
}
