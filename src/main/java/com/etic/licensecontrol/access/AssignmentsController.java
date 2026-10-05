package com.etic.licensecontrol.access;

import com.etic.licensecontrol.common.CrudService;
import java.util.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController @RequestMapping("/api/admin")
public class AssignmentsController {
    private final CrudService c;private final AttributeValueService values;
    AssignmentsController(CrudService c,AttributeValueService values){this.c=c;this.values=values;}
    private static final CrudService.Definition OPTIONS=new CrudService.Definition("system_attribute_options","Id_Option",List.of("Value_Code","Display_Name","Sort_Order"),List.of("Value_Code","Display_Name"));
    private Map<String,Object> key(String user,String system){return Map.of("u",user,"s",system);}
    private void requireAccess(String user,String system){
        if(c.db().queryForObject("SELECT COUNT(*) FROM user_system_access a JOIN users u ON u.Id_User=a.Id_User JOIN systems s ON s.Id_System=a.Id_System WHERE a.Id_User=:u AND a.Id_System=:s AND a.Is_Active=TRUE AND u.Is_Active=TRUE AND s.Is_Active=TRUE",key(user,system),Integer.class)==0)throw new IllegalArgumentException("Asigne primero un sistema activo al usuario");
    }
    @GetMapping("/users/{userId}/systems") List<Map<String,Object>> systems(@PathVariable String userId){return c.db().queryForList("SELECT usa.*,s.Code System_Code,s.Name System_Name FROM user_system_access usa JOIN systems s ON s.Id_System=usa.Id_System WHERE usa.Id_User=:u AND usa.Is_Active=TRUE AND s.Is_Active=TRUE",Map.of("u",userId)).stream().map(CrudService::formatDates).toList();}
    @PostMapping("/users/{userId}/systems") @Transactional void system(@PathVariable String userId,@RequestBody Map<String,Object>b){
        Object system=b.get("Id_System");if(system==null)throw new IllegalArgumentException("Sistema obligatorio");
        var p=new HashMap<String,Object>(key(userId,system.toString()));p.put("id",UUID.randomUUID().toString());
        if(c.db().queryForObject("SELECT COUNT(*) FROM users u CROSS JOIN systems s WHERE u.Id_User=:u AND s.Id_System=:s AND u.Is_Active=TRUE AND s.Is_Active=TRUE",p,Integer.class)==0)throw new IllegalArgumentException("Usuario o sistema inactivo");
        c.db().update("INSERT INTO user_system_access(Id_User_System_Access,Id_User,Id_System) VALUES(:id,:u,:s) ON DUPLICATE KEY UPDATE Is_Active=TRUE",p);
        c.audit("user_system_access",userId,"ASSIGN");
    }
    @PutMapping("/users/{userId}/systems/{systemId}") void access(@PathVariable String userId,@PathVariable String systemId,@RequestBody Map<String,Object> body){system(userId,Map.of("Id_System",systemId));}
    @DeleteMapping("/users/{userId}/systems/{systemId}") @Transactional void removeSystem(@PathVariable String userId,@PathVariable String systemId){
        c.db().update("UPDATE user_system_access SET Is_Active=FALSE WHERE Id_User=:u AND Id_System=:s",key(userId,systemId));
        c.audit("user_system_access",userId,"UNASSIGN");
    }
    @GetMapping("/users/{userId}/systems/{systemId}/roles") List<Map<String,Object>> roles(@PathVariable String userId,@PathVariable String systemId){
        requireAccess(userId,systemId);
        return c.db().queryForList("SELECT r.*,IF(usr.Id_User IS NULL,FALSE,TRUE) Assigned FROM roles r LEFT JOIN user_system_roles usr ON usr.Id_Role=r.Id_Role AND usr.Id_User=:u AND usr.Id_System=:s AND usr.Is_Active=TRUE WHERE r.Id_System=:s AND r.Is_Active=TRUE",key(userId,systemId)).stream().map(CrudService::formatDates).toList();
    }
    @PutMapping("/users/{userId}/systems/{systemId}/roles") @Transactional void roles(@PathVariable String userId,@PathVariable String systemId,@RequestBody List<String> ids){
        requireAccess(userId,systemId);var p=new HashMap<String,Object>(key(userId,systemId));Set<String> selected=new HashSet<>(ids);
        for(String role:selected){p.put("r",role);if(c.db().queryForObject("SELECT COUNT(*) FROM roles WHERE Id_Role=:r AND Id_System=:s AND Is_Active=TRUE",p,Integer.class)==0)throw new IllegalArgumentException("El rol no pertenece al sistema o está inactivo");}
        if(selected.isEmpty())c.db().update("UPDATE user_system_roles SET Is_Active=FALSE WHERE Id_User=:u AND Id_System=:s",p);
        else{p.put("selected",selected);c.db().update("UPDATE user_system_roles SET Is_Active=FALSE WHERE Id_User=:u AND Id_System=:s AND Id_Role NOT IN (:selected)",p);}
        for(String role:selected){p.put("r",role);c.db().update("INSERT INTO user_system_roles(Id_User,Id_System,Id_Role) VALUES(:u,:s,:r) ON DUPLICATE KEY UPDATE Is_Active=TRUE",p);}
        c.audit("user_system_roles",userId,"UPDATE");
    }
    @GetMapping("/roles/{roleId}/permissions") List<Map<String,Object>> permissions(@PathVariable String roleId){return c.db().queryForList("SELECT p.*,IF(rp.Id_Role IS NULL,FALSE,TRUE) Assigned FROM permissions p JOIN roles r ON r.Id_System=p.Id_System LEFT JOIN role_permissions rp ON rp.Id_Permission=p.Id_Permission AND rp.Id_Role=r.Id_Role AND rp.Is_Active=TRUE WHERE r.Id_Role=:r AND r.Is_Active=TRUE AND p.Is_Active=TRUE",Map.of("r",roleId)).stream().map(CrudService::formatDates).toList();}
    @PutMapping("/roles/{roleId}/permissions") @Transactional void permissions(@PathVariable String roleId,@RequestBody List<String> ids){
        var p=new HashMap<String,Object>();p.put("r",roleId);Set<String> selected=new HashSet<>(ids);
        if(c.db().queryForObject("SELECT COUNT(*) FROM roles r JOIN systems s ON s.Id_System=r.Id_System WHERE r.Id_Role=:r AND r.Is_Active=TRUE AND s.Is_Active=TRUE",p,Integer.class)==0)throw new IllegalArgumentException("Rol inválido");
        for(String permission:selected){p.put("p",permission);if(c.db().queryForObject("SELECT COUNT(*) FROM roles r JOIN permissions p ON p.Id_System=r.Id_System WHERE r.Id_Role=:r AND p.Id_Permission=:p AND p.Is_Active=TRUE",p,Integer.class)==0)throw new IllegalArgumentException("El permiso no pertenece al sistema del rol");}
        if(selected.isEmpty())c.db().update("UPDATE role_permissions SET Is_Active=FALSE WHERE Id_Role=:r",p);
        else{p.put("selected",selected);c.db().update("UPDATE role_permissions SET Is_Active=FALSE WHERE Id_Role=:r AND Id_Permission NOT IN (:selected)",p);}
        for(String permission:selected){p.put("p",permission);c.db().update("INSERT INTO role_permissions(Id_Role,Id_Permission) VALUES(:r,:p) ON DUPLICATE KEY UPDATE Is_Active=TRUE",p);}
        c.audit("role_permissions",roleId,"UPDATE");
    }
    @GetMapping("/attributes/{attributeId}/options") List<Map<String,Object>> options(@PathVariable String attributeId){return c.db().queryForList("SELECT * FROM system_attribute_options WHERE Id_Attribute=:a AND Is_Active=TRUE ORDER BY Sort_Order",Map.of("a",attributeId)).stream().map(CrudService::formatDates).toList();}
    @PostMapping("/attributes/{attributeId}/options") @Transactional void option(@PathVariable String attributeId,@RequestBody Map<String,Object>b){
        b.remove("Status");b.remove("Is_Active");b.putIfAbsent("Sort_Order",0);
        new com.etic.licensecontrol.common.InputValidator(c.db()).validate("system_attribute_options",b);
        Map<String,Object>p=new HashMap<>(b);p.put("id",UUID.randomUUID().toString());p.put("a",attributeId);
        if(c.db().queryForObject("SELECT COUNT(*) FROM system_attributes WHERE Id_Attribute=:a AND Is_Active=TRUE",p,Integer.class)==0)throw new IllegalArgumentException("Atributo inactivo");
        c.db().update("INSERT INTO system_attribute_options(Id_Option,Id_Attribute,Value_Code,Display_Name,Sort_Order) VALUES(:id,:a,:Value_Code,:Display_Name,:Sort_Order) ON DUPLICATE KEY UPDATE Is_Active=TRUE,Display_Name=VALUES(Display_Name),Sort_Order=VALUES(Sort_Order)",p);
        c.audit("system_attribute_options",attributeId,"UPDATE");
    }
    @PutMapping("/attributes/{attributeId}/options/{id}") Map<String,Object> optionUpdate(@PathVariable String attributeId,@PathVariable String id,@RequestBody Map<String,Object> body){if(!attributeId.equals(c.get(OPTIONS,id).get("Id_Attribute")))throw new IllegalArgumentException("Opción inválida");return c.update(OPTIONS,id,body);}
    @DeleteMapping("/attributes/{attributeId}/options/{id}") void removeOption(@PathVariable String attributeId,@PathVariable String id){if(!attributeId.equals(c.get(OPTIONS,id).get("Id_Attribute")))throw new IllegalArgumentException("Opción inválida");c.deactivate(OPTIONS,id);}
    @GetMapping("/users/{userId}/systems/{systemId}/attributes") List<Map<String,Object>> values(@PathVariable String userId,@PathVariable String systemId){requireAccess(userId,systemId);return c.db().queryForList("SELECT a.*,v.Id_User_Attribute_Value,v.Value_Text,v.Value_Integer,v.Value_Decimal,v.Value_Boolean,v.Value_Date,v.Value_Datetime,v.Value_Json FROM system_attributes a LEFT JOIN user_system_attribute_values v ON v.Id_Attribute=a.Id_Attribute AND v.Id_User=:u AND v.Id_System=:s WHERE a.Id_System=:s AND a.Is_Active=TRUE ORDER BY a.Sort_Order",key(userId,systemId)).stream().map(CrudService::formatDates).toList();}
    @PutMapping("/users/{userId}/systems/{systemId}/attributes/{attributeId}") void value(@PathVariable String userId,@PathVariable String systemId,@PathVariable String attributeId,@RequestBody Map<String,Object>b){values.save(userId,systemId,attributeId,b);}
}
