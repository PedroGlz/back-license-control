package com.etic.licensecontrol.licensing;

import com.etic.licensecontrol.common.CrudService;
import java.time.*;
import java.sql.Timestamp;
import java.util.*;
import org.springframework.jdbc.core.namedparam.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Service
public class EntitlementService {
    private final NamedParameterJdbcTemplate db;
    private final CrudService crud;
    public EntitlementService(CrudService crud) { this.crud=crud;this.db=crud.db(); }
    public static final String OCCUPIED="SELECT COUNT(*) FROM licenses WHERE Id_Entitlement=:id AND Status IN ('ACTIVE','SUSPENDED')";
    public List<Map<String,Object>> list() {
        var rows=db.queryForList("SELECT e.*,c.Name Customer_Name,c.Email Customer_Email,s.Name System_Name,(SELECT COUNT(*) FROM licenses l WHERE l.Id_Entitlement=e.Id_Entitlement AND l.Status IN ('ACTIVE','SUSPENDED')) Used_Seats FROM license_entitlements e JOIN customers c ON c.Id_Customer=e.Id_Customer JOIN systems s ON s.Id_System=e.Id_System WHERE e.Is_Active=TRUE ORDER BY e.Created_At DESC",Map.of());
        rows.forEach(this::format);return rows;
    }
    public Map<String,Object> detail(String id) {
        var row=list().stream().filter(r->id.equals(r.get("Id_Entitlement"))).findFirst().orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Licencia no encontrada"));
        row.put("devices",db.queryForList("SELECT l.Id_License,l.Status License_Status,d.Id_Device,d.Display_Name,d.Manufacturer,d.Model,d.Android_Version,d.App_Version,d.Status,d.Enrolled_At,d.Last_Validation_At FROM licenses l JOIN licensed_devices d ON d.Id_Device=l.Id_Device WHERE l.Id_Entitlement=:id ORDER BY l.Created_At DESC",Map.of("id",id)).stream().map(CrudService::formatDates).toList());return row;
    }
    @Transactional public Map<String,Object> create(Map<String,Object> body,String actor) {
        String customer=required(body,"Id_Customer"),system=required(body,"Id_System"),term=required(body,"Term_Type");
        int seats;try{seats=Integer.parseInt(Objects.toString(body.get("Seat_Count"),""));}catch(Exception ex){throw new IllegalArgumentException("La cantidad de dispositivos debe ser un entero positivo");}
        if(seats<1)throw new IllegalArgumentException("La cantidad de dispositivos debe ser positiva");
        var p=new MapSqlParameterSource().addValue("customer",customer).addValue("system",system);
        if(db.queryForObject("SELECT COUNT(*) FROM customers WHERE Id_Customer=:customer AND Is_Active=TRUE",p,Integer.class)!=1)throw new IllegalArgumentException("Selecciona un cliente activo");
        if(db.queryForObject("SELECT COUNT(*) FROM systems s JOIN system_licensing sl ON sl.Id_System=s.Id_System WHERE s.Id_System=:system AND s.Is_Active=TRUE AND s.Status='ACTIVE' AND s.System_Type='ANDROID' AND sl.Is_Active=TRUE AND sl.Licensing_Mode='DEVICE_ONLY'",p,Integer.class)!=1)throw new IllegalArgumentException("Selecciona un sistema DEVICE_ONLY activo");
        LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC);
        LocalDateTime until=switch(term){case "MONTHLY"->now.plusMonths(1);case "ANNUAL"->now.plusYears(1);case "PERPETUAL"->null;default->throw new IllegalArgumentException("Vigencia inválida");};
        String id=UUID.randomUUID().toString();p.addValue("id",id).addValue("term",term).addValue("seats",seats).addValue("now",now).addValue("until",until).addValue("actor",actor);
        db.update("INSERT INTO license_entitlements(Id_Entitlement,Id_Customer,Id_System,Term_Type,Seat_Count,Activated_At,Expires_At,Created_By) VALUES(:id,:customer,:system,:term,:seats,:now,:until,:actor)",p);
        crud.audit("license_entitlements",id,"CREATE");return detail(id);
    }
    @Transactional public void status(String id,String target,String actor) {
        var row=lock(id);String previous=row.get("Status").toString();
        if("REVOKED".equals(previous))throw new IllegalArgumentException("Una licencia revocada no puede reactivarse");
        if(!Set.of("ACTIVE","SUSPENDED","REVOKED").contains(target)||previous.equals(target)||"ACTIVE".equals(target)&&!"SUSPENDED".equals(previous))throw new IllegalArgumentException("Cambio de estado no permitido");
        if("ACTIVE".equals(target)&&expired(row))throw new IllegalArgumentException("La licencia está vencida");
        db.update("UPDATE license_entitlements SET Status=:status,Updated_By=:actor WHERE Id_Entitlement=:id",Map.of("status",target,"actor",actor,"id",id));
        if("REVOKED".equals(target)) {
            db.update("UPDATE licenses SET Status='REVOKED',Updated_At=UTC_TIMESTAMP(),Updated_By=:actor WHERE Id_Entitlement=:id AND Status<>'REVOKED'",Map.of("id",id,"actor",actor));
            db.update("UPDATE device_enrollment_codes SET Revoked_At=UTC_TIMESTAMP() WHERE Id_Entitlement=:id AND Used_At IS NULL AND Revoked_At IS NULL",Map.of("id",id));
        }
        crud.audit("license_entitlements",id,target);
    }
    public Map<String,Object> lock(String id) {
        if(id==null||id.isBlank())throw new IllegalArgumentException("Selecciona una licencia comercial");
        var rows=db.queryForList("SELECT e.*,s.Code,s.Package_Name,s.System_Type,s.Is_Active System_Active,s.Status System_Status,sl.Offline_Validity_Days,sl.Is_Active Licensing_Active,sl.Licensing_Mode FROM license_entitlements e JOIN systems s ON s.Id_System=e.Id_System JOIN system_licensing sl ON sl.Id_System=e.Id_System WHERE e.Id_Entitlement=:id FOR UPDATE",Map.of("id",id));
        if(rows.isEmpty())throw denied("LICENSE_REVOKED","Licencia no disponible");return rows.getFirst();
    }
    public Map<String,Object> usable(String id) {
        var e=lock(id);
        if(!enabled(e.get("Is_Active"))||"REVOKED".equals(e.get("Status")))throw denied("LICENSE_REVOKED","Licencia revocada");
        if("SUSPENDED".equals(e.get("Status")))throw denied("LICENSE_SUSPENDED","Licencia suspendida");
        if(expired(e))throw denied("LICENSE_EXPIRED","Licencia vencida");
        if(!"ACTIVE".equals(e.get("Status"))||!"ANDROID".equals(e.get("System_Type"))||!enabled(e.get("System_Active"))||!"ACTIVE".equals(e.get("System_Status"))||!enabled(e.get("Licensing_Active"))||!"DEVICE_ONLY".equals(e.get("Licensing_Mode")))throw denied("LICENSE_REVOKED","Sistema no disponible");
        return e;
    }
    public int used(String id) { return db.queryForObject(OCCUPIED,Map.of("id",id),Integer.class); }
    @Transactional public void retireDevice(String device,String reason,String actor) {
        if(!Set.of("LOST","REPLACED","REVOKED").contains(reason))throw new IllegalArgumentException("Acción inválida");
        var owners=db.queryForList("SELECT DISTINCT Id_Entitlement FROM licenses WHERE Id_Device=:device AND Id_Entitlement IS NOT NULL ORDER BY Id_Entitlement",Map.of("device",device));
        if(owners.isEmpty())throw new IllegalArgumentException("El dispositivo no tiene una licencia DEVICE_ONLY");
        owners.forEach(r->lock(r.get("Id_Entitlement").toString()));
        var p=Map.of("device",device,"actor",actor);
        db.update("UPDATE licenses SET Status='REVOKED',Updated_At=UTC_TIMESTAMP(),Updated_By=:actor WHERE Id_Device=:device AND Id_Entitlement IS NOT NULL",p);
        db.update("UPDATE licensed_devices SET Status='REVOKED',Updated_At=UTC_TIMESTAMP(),Updated_By=:actor WHERE Id_Device=:device",p);
        crud.audit("licensed_devices",device,reason);
    }
    public Map<String,Object> dashboard() {
        return Map.of("activeCustomers",db.queryForObject("SELECT COUNT(*) FROM customers WHERE Is_Active=TRUE",Map.of(),Long.class),
            "activeLicenses",db.queryForObject("SELECT COUNT(*) FROM license_entitlements WHERE Is_Active=TRUE AND Status='ACTIVE' AND (Expires_At IS NULL OR Expires_At>UTC_TIMESTAMP())",Map.of(),Long.class),
            "suspendedLicenses",db.queryForObject("SELECT COUNT(*) FROM license_entitlements WHERE Is_Active=TRUE AND Status='SUSPENDED' AND (Expires_At IS NULL OR Expires_At>UTC_TIMESTAMP())",Map.of(),Long.class),
            "expiringLicenses",db.queryForObject("SELECT COUNT(*) FROM license_entitlements WHERE Is_Active=TRUE AND Status='ACTIVE' AND Expires_At BETWEEN UTC_TIMESTAMP() AND DATE_ADD(UTC_TIMESTAMP(),INTERVAL 30 DAY)",Map.of(),Long.class),
            "availableSeats",list().stream().filter(r->"ACTIVE".equals(r.get("Effective_Status"))).mapToLong(r->((Number)r.get("Available_Seats")).longValue()).sum(),
            "activeDevices",db.queryForObject("SELECT COUNT(*) FROM licensed_devices WHERE Is_Active=TRUE AND Status='ACTIVE'",Map.of(),Long.class));
    }
    private void format(Map<String,Object> row) {
        row.put("Effective_Status",!"REVOKED".equals(row.get("Status"))&&expired(row)?"EXPIRED":row.get("Status"));
        row.put("Available_Seats",Math.max(0,((Number)row.get("Seat_Count")).intValue()-((Number)row.get("Used_Seats")).intValue()));
        row.replaceAll((k,v)->v instanceof Timestamp t?t.toLocalDateTime().toString()+"Z":v instanceof LocalDateTime time?time.toString()+"Z":v);
    }
    public static Instant expiry(Map<String,Object> row) { Object value=row.get("Expires_At");return value==null?null:(value instanceof Timestamp t?t.toLocalDateTime():LocalDateTime.parse(value.toString())).toInstant(ZoneOffset.UTC); }
    private static boolean expired(Map<String,Object> row) { Instant until=expiry(row);return until!=null&&!until.isAfter(Instant.now()); }
    private static boolean enabled(Object v) { return Boolean.TRUE.equals(v)||v instanceof Number n&&n.intValue()!=0; }
    private static String required(Map<String,Object> body,String key) { String v=Objects.toString(body.get(key),"");if(v.isBlank())throw new IllegalArgumentException("Completa los campos obligatorios");return v; }
    public static ResponseStatusException denied(String code,String text) { return new ResponseStatusException(HttpStatus.FORBIDDEN,code+": "+text); }
}
