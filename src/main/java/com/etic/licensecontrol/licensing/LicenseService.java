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
public class LicenseService {
    private final NamedParameterJdbcTemplate db;
    private final CrudService crud;
    public LicenseService(CrudService crud) { this.crud=crud;this.db=crud.db(); }
    public List<Map<String,Object>> list() {
        var rows=db.queryForList("SELECT l.*,c.Name Customer_Name,c.Email Customer_Email,u.Username User_Name,s.Name System_Name,(SELECT COUNT(*) FROM license_devices ld WHERE ld.Id_License=l.Id_License AND ld.Status IN ('ACTIVE','SUSPENDED')) Used_Seats FROM licenses l LEFT JOIN customers c ON c.Id_Customer=l.Id_Customer LEFT JOIN users u ON u.Id_User=l.Id_User JOIN systems s ON s.Id_System=l.Id_System WHERE l.Is_Active=TRUE ORDER BY l.Created_At DESC",Map.of());
        rows.forEach(this::format);return rows;
    }
    public Map<String,Object> detail(String id) {
        var row=list().stream().filter(r->id.equals(r.get("Id_License"))).findFirst().orElseThrow(()->denied("LICENSE_NOT_FOUND","Licencia no encontrada"));
        row.put("devices",db.queryForList("SELECT ld.Id_License_Device,ld.Status License_Status,d.Id_Device,d.Display_Name,d.Manufacturer,d.Model,d.Android_Version,d.App_Version,d.Status,ld.Activated_At,d.Last_Validation_At FROM license_devices ld JOIN licensed_devices d ON d.Id_Device=ld.Id_Device WHERE ld.Id_License=:id ORDER BY ld.Created_At DESC",Map.of("id",id)).stream().map(CrudService::formatDates).toList());return row;
    }
    @Transactional public Map<String,Object> create(Map<String,Object> body,String actor) {
        String system=required(body,"Id_System"),term=required(body,"Term_Type");
        int seats;try{seats=Integer.parseInt(Objects.toString(body.get("Seat_Count"),""));}catch(Exception ex){throw new IllegalArgumentException("La cantidad de dispositivos debe ser un entero positivo");}
        if(seats<1)throw new IllegalArgumentException("La cantidad de dispositivos debe ser positiva");
        var p=new MapSqlParameterSource().addValue("system",system);
        var configs=db.queryForList("SELECT sl.Licensing_Mode FROM systems s JOIN system_licensing sl ON sl.Id_System=s.Id_System WHERE s.Id_System=:system AND s.Is_Active=TRUE AND s.Status='ACTIVE' AND s.System_Type='ANDROID' AND sl.Is_Active=TRUE FOR UPDATE",p);
        if(configs.size()!=1)throw new IllegalArgumentException("Selecciona un sistema Android con licenciamiento activo");
        String mode=configs.getFirst().get("Licensing_Mode").toString();
        String customer=optional(body,"Id_Customer"),user=null;
        if("DEVICE_ONLY".equals(mode))customer=required(body,"Id_Customer");
        else if("USER_DEVICE".equals(mode))user=required(body,"Id_User");
        else throw new IllegalArgumentException("Modalidad inválida");
        p.addValue("customer",customer).addValue("user",user).addValue("mode",mode);
        if(customer!=null&&db.queryForObject("SELECT COUNT(*) FROM customers WHERE Id_Customer=:customer AND Is_Active=TRUE",p,Integer.class)!=1)throw new IllegalArgumentException("Selecciona un cliente activo");
        if(user!=null&&db.queryForObject("SELECT COUNT(*) FROM users WHERE Id_User=:user AND Is_Active=TRUE AND Status NOT IN ('SUSPENDED','LOCKED')",p,Integer.class)!=1)throw new IllegalArgumentException("Selecciona un usuario activo");
        LocalDateTime now=LocalDateTime.now(ZoneOffset.UTC);
        LocalDateTime until=switch(term){case "MONTHLY"->now.plusMonths(1);case "ANNUAL"->now.plusYears(1);case "PERPETUAL"->null;default->throw new IllegalArgumentException("Vigencia inválida");};
        String id=UUID.randomUUID().toString();p.addValue("id",id).addValue("term",term).addValue("seats",seats).addValue("now",now).addValue("until",until).addValue("actor",actor);
        db.update("INSERT INTO licenses(Id_License,Id_System,Licensing_Mode,Id_Customer,Id_User,Term_Type,Seat_Count,Activated_At,Expires_At,Created_By) VALUES(:id,:system,:mode,:customer,:user,:term,:seats,:now,:until,:actor)",p);
        crud.audit("licenses",id,"CREATE");return detail(id);
    }
    @Transactional public void status(String id,String target,String actor) {
        var row=lock(id);String previous=row.get("Status").toString();
        if("REVOKED".equals(previous))throw new IllegalArgumentException("Una licencia revocada no puede reactivarse");
        if(!Set.of("ACTIVE","SUSPENDED","REVOKED").contains(target)||previous.equals(target)||"ACTIVE".equals(target)&&!"SUSPENDED".equals(previous))throw new IllegalArgumentException("Cambio de estado no permitido");
        if("ACTIVE".equals(target)&&expired(row))throw new IllegalArgumentException("La licencia está vencida");
        db.update("UPDATE licenses SET Status=:status,Modified_At=UTC_TIMESTAMP(6),Modified_By=:actor WHERE Id_License=:id",Map.of("status",target,"actor",actor,"id",id));
        if("REVOKED".equals(target))
            db.update("UPDATE license_devices SET Status='REVOKED',Revoked_At=UTC_TIMESTAMP(6) WHERE Id_License=:id AND Status IN ('ACTIVE','SUSPENDED')",Map.of("id",id));
        crud.audit("licenses",id,target);
    }
    public Map<String,Object> lock(String id) {
        if(id==null||id.isBlank())throw denied("LICENSE_NOT_FOUND","Selecciona una licencia");
        var rows=db.queryForList("SELECT l.*,s.Code,s.System_Type,s.Is_Active System_Active,s.Status System_Status,sl.Package_Name,sl.Offline_Validity_Days,sl.Is_Active Licensing_Active,sl.Licensing_Mode Configured_Mode FROM licenses l JOIN systems s ON s.Id_System=l.Id_System JOIN system_licensing sl ON sl.Id_System=l.Id_System WHERE l.Id_License=:id FOR UPDATE",Map.of("id",id));
        if(rows.isEmpty())throw denied("LICENSE_NOT_FOUND","Licencia no encontrada");return rows.getFirst();
    }
    public Map<String,Object> usable(String id) {
        var l=lock(id);
        if(!enabled(l.get("Is_Active"))||"REVOKED".equals(l.get("Status")))throw denied("LICENSE_REVOKED","Licencia revocada");
        if("SUSPENDED".equals(l.get("Status")))throw denied("LICENSE_SUSPENDED","Licencia suspendida");
        if(expired(l))throw denied("LICENSE_EXPIRED","Licencia vencida");
        if(!"ACTIVE".equals(l.get("Status"))||!"ANDROID".equals(l.get("System_Type"))||!enabled(l.get("System_Active"))||!"ACTIVE".equals(l.get("System_Status"))||!enabled(l.get("Licensing_Active"))||!Objects.equals(l.get("Licensing_Mode"),l.get("Configured_Mode")))throw denied("LICENSE_REVOKED","Sistema no disponible");
        if("USER_DEVICE".equals(l.get("Licensing_Mode"))&&db.queryForObject("SELECT COUNT(*) FROM users WHERE Id_User=:user AND Is_Active=TRUE AND Status NOT IN ('SUSPENDED','LOCKED')",Map.of("user",l.get("Id_User")),Integer.class)!=1)throw denied("LICENSE_REVOKED","Usuario no disponible");
        return l;
    }
    @Transactional public void linkUserDevice(String id,String device,String actor) {
        var license=usable(id);
        if(!"USER_DEVICE".equals(license.get("Licensing_Mode")))throw new IllegalArgumentException("DEVICE_ONLY requiere enrollment mediante código");
        if(device==null||device.isBlank())throw new IllegalArgumentException("Selecciona un dispositivo registrado");
        var p=Map.of("id",id,"device",device);
        var devices=db.queryForList("SELECT Id_Device FROM licensed_devices WHERE Id_Device=:device AND Is_Active=TRUE AND Status='ACTIVE' FOR UPDATE",p);
        if(devices.isEmpty())throw denied("DEVICE_REVOKED","Dispositivo no autorizado");
        if(!db.queryForList("SELECT Id_License_Device FROM license_devices WHERE Id_License=:id AND Id_Device=:device FOR UPDATE",p).isEmpty())throw new IllegalArgumentException("El dispositivo ya tiene un vínculo con esta licencia");
        if(used(id)>=((Number)license.get("Seat_Count")).intValue())throw denied("NO_SEATS_AVAILABLE","No hay dispositivos disponibles en esta licencia");
        db.update("INSERT INTO license_devices(Id_License_Device,Id_License,Id_Device) VALUES(:link,:id,:device)",new MapSqlParameterSource(p).addValue("link",UUID.randomUUID().toString()));
        crud.audit("licenses",id,"DEVICE_LINKED");
    }
    public int used(String id) { return db.queryForList("SELECT Id_License_Device FROM license_devices WHERE Id_License=:id AND Status IN ('ACTIVE','SUSPENDED') FOR UPDATE",Map.of("id",id)).size(); }
    @Transactional public void retireDevice(String device,String reason,String actor) {
        if(!Set.of("LOST","REPLACED","REVOKED").contains(reason))throw new IllegalArgumentException("Acción inválida");
        var owners=db.queryForList("SELECT DISTINCT Id_License FROM license_devices WHERE Id_Device=:device ORDER BY Id_License",Map.of("device",device));
        if(owners.isEmpty())throw new IllegalArgumentException("Dispositivo no encontrado");
        owners.forEach(r->lock(r.get("Id_License").toString()));
        var p=Map.of("device",device,"reason",reason);
        db.update("UPDATE license_devices SET Status=:reason,Revoked_At=UTC_TIMESTAMP(6) WHERE Id_Device=:device AND Status IN ('ACTIVE','SUSPENDED')",p);
        db.update("UPDATE licensed_devices SET Status=:reason,Modified_At=UTC_TIMESTAMP(6) WHERE Id_Device=:device",p);
        crud.audit("licensed_devices",device,reason);
    }
    public Map<String,Object> dashboard() {
        return Map.of("activeCustomers",db.queryForObject("SELECT COUNT(*) FROM customers WHERE Is_Active=TRUE",Map.of(),Long.class),
            "activeLicenses",db.queryForObject("SELECT COUNT(*) FROM licenses WHERE Is_Active=TRUE AND Status='ACTIVE' AND (Expires_At IS NULL OR Expires_At>UTC_TIMESTAMP())",Map.of(),Long.class),
            "suspendedLicenses",db.queryForObject("SELECT COUNT(*) FROM licenses WHERE Is_Active=TRUE AND Status='SUSPENDED' AND (Expires_At IS NULL OR Expires_At>UTC_TIMESTAMP())",Map.of(),Long.class),
            "expiringLicenses",db.queryForObject("SELECT COUNT(*) FROM licenses WHERE Is_Active=TRUE AND Status='ACTIVE' AND Expires_At BETWEEN UTC_TIMESTAMP() AND DATE_ADD(UTC_TIMESTAMP(),INTERVAL 30 DAY)",Map.of(),Long.class),
            "availableSeats",list().stream().filter(r->"ACTIVE".equals(r.get("Effective_Status"))).mapToLong(r->((Number)r.get("Available_Seats")).longValue()).sum(),
            "activeDevices",db.queryForObject("SELECT COUNT(*) FROM licensed_devices WHERE Is_Active=TRUE AND Status='ACTIVE'",Map.of(),Long.class));
    }
    private void format(Map<String,Object> row) {
        row.put("Effective_Status",!"REVOKED".equals(row.get("Status"))&&expired(row)?"EXPIRED":row.get("Status"));
        row.put("Available_Seats",Math.max(0,((Number)row.get("Seat_Count")).intValue()-((Number)row.get("Used_Seats")).intValue()));
        row.replaceAll((k,v)->v instanceof Timestamp t?t.toLocalDateTime().toString()+"Z":v instanceof LocalDateTime time?time.toString()+"Z":v);
    }
    public static Instant expiry(Map<String,Object> row) { Object v=row.get("Expires_At");return v==null?null:(v instanceof Timestamp t?t.toLocalDateTime():v instanceof LocalDateTime t?t:LocalDateTime.parse(v.toString())).toInstant(ZoneOffset.UTC); }
    private static boolean expired(Map<String,Object> row) { Instant until=expiry(row);return until!=null&&!until.isAfter(Instant.now()); }
    private static boolean enabled(Object v) { return Boolean.TRUE.equals(v)||v instanceof Number n&&n.intValue()!=0; }
    private static String optional(Map<String,Object> body,String key) { String v=Objects.toString(body.get(key),"").trim();return v.isEmpty()?null:v; }
    private static String required(Map<String,Object> body,String key) { String v=optional(body,key);if(v==null)throw new IllegalArgumentException("Completa los campos obligatorios");return v; }
    public static ResponseStatusException denied(String code,String text) { return new ResponseStatusException(HttpStatus.FORBIDDEN,code+": "+text); }
}
