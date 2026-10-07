package com.etic.licensecontrol.access;

import com.etic.licensecontrol.common.CrudService;
import java.util.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController @RequestMapping("/api/admin")
public class AssignmentsController {
    private final CrudService c;private final AttributeValueService values;
    AssignmentsController(CrudService c,AttributeValueService values){this.c=c;this.values=values;}
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
    // Display_Name se conserva como alias del contrato consumido por los selectores de atributos.
    private static final String OPTION_SELECT="SELECT Id_Option,Id_Attribute,Value_Code,Display_Value AS Display_Name,Sort_Order,Is_Active,Created_At,Updated_At FROM system_attribute_options";
    @GetMapping("/attributes/{attributeId}/options")
    List<Map<String,Object>> options(@PathVariable String attributeId,@RequestParam(defaultValue="false") boolean includeInactive){
        requireAttribute(attributeId,false);
        return c.db().queryForList(OPTION_SELECT+" WHERE Id_Attribute=:a"+(includeInactive?"":" AND Is_Active=TRUE")+" ORDER BY Sort_Order,Display_Value,Id_Option",Map.of("a",attributeId)).stream().map(CrudService::formatDates).toList();
    }
    @PostMapping("/attributes/{attributeId}/options") @Transactional
    Map<String,Object> option(@PathVariable String attributeId,@RequestBody Map<String,Object> body){
        requireAttribute(attributeId,true);
        var p=optionParams(body,null);p.put("a",attributeId);p.put("id",UUID.randomUUID().toString());
        requireUniqueOption(p);
        c.db().update("INSERT INTO system_attribute_options(Id_Option,Id_Attribute,Value_Code,Display_Value,Sort_Order,Is_Active) VALUES(:id,:a,:value,:label,:sort,:active)",p);
        c.audit("system_attribute_options",p.get("id").toString(),"CREATE");
        return findOption(attributeId,p.get("id").toString());
    }
    @PutMapping("/attributes/{attributeId}/options/{id}") @Transactional
    Map<String,Object> optionUpdate(@PathVariable String attributeId,@PathVariable String id,@RequestBody Map<String,Object> body){
        requireAttribute(attributeId,true);
        var original=findOption(attributeId,id);var p=optionParams(body,original);p.put("a",attributeId);p.put("id",id);
        requireUniqueOption(p);
        if(!Objects.equals(original.get("Value_Code"),p.get("value"))){
            p.put("old",original.get("Value_Code"));
            if(c.db().queryForObject("SELECT COUNT(*) FROM user_system_attribute_values WHERE Id_Attribute=:a AND (Value_Text=:old OR JSON_CONTAINS(Value_Json,JSON_QUOTE(:old)))",p,Integer.class)>0)
                throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,"El valor está asignado a usuarios y no puede cambiarse. Puedes editar su etiqueta.");
        }
        c.db().update("UPDATE system_attribute_options SET Value_Code=:value,Display_Value=:label,Sort_Order=:sort,Is_Active=:active WHERE Id_Option=:id AND Id_Attribute=:a",p);
        c.audit("system_attribute_options",id,"UPDATE");
        return findOption(attributeId,id);
    }
    @DeleteMapping("/attributes/{attributeId}/options/{id}") @Transactional
    void removeOption(@PathVariable String attributeId,@PathVariable String id){
        requireAttribute(attributeId,true);findOption(attributeId,id);
        c.db().update("UPDATE system_attribute_options SET Is_Active=FALSE WHERE Id_Option=:id AND Id_Attribute=:a",Map.of("id",id,"a",attributeId));
        c.audit("system_attribute_options",id,"DEACTIVATE");
    }
    private void requireAttribute(String id,boolean lock){
        var rows=c.db().queryForList("SELECT Data_Type FROM system_attributes WHERE Id_Attribute=:a AND Is_Active=TRUE"+(lock?" FOR UPDATE":""),Map.of("a",id));
        if(rows.isEmpty())throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND,"Atributo no encontrado");
        if(lock&&!Set.of("SELECT","MULTISELECT").contains(rows.getFirst().get("Data_Type")))
            throw new IllegalArgumentException("Este tipo de atributo no admite opciones");
    }
    private Map<String,Object> findOption(String attribute,String id){
        return c.db().queryForList(OPTION_SELECT+" WHERE Id_Attribute=:a AND Id_Option=:id",Map.of("a",attribute,"id",id)).stream().findFirst().map(CrudService::formatDates)
            .orElseThrow(()->new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND,"Opción no encontrada"));
    }
    private void requireUniqueOption(Map<String,Object> p){
        if(c.db().queryForObject("SELECT COUNT(*) FROM system_attribute_options WHERE Id_Attribute=:a AND Value_Code=:value AND Id_Option<>:id",p,Integer.class)>0)
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,"Ya existe este valor en el atributo. Edita o reactiva la opción existente.");
    }
    private Map<String,Object> optionParams(Map<String,Object> body,Map<String,Object> original){
        var merged=new HashMap<String,Object>();if(original!=null)merged.putAll(original);merged.putAll(body);
        Object raw=merged.get("Value_Code");if(!(raw instanceof String value)||value.isBlank()||value.length()>100)throw new IllegalArgumentException("El valor es obligatorio y admite hasta 100 caracteres");
        Object label=merged.get("Display_Name");if(label!=null&&!(label instanceof String))throw new IllegalArgumentException("Etiqueta inválida");
        String text=label==null||label.toString().isBlank()?value.trim():label.toString().trim();
        if(text.length()>150)throw new IllegalArgumentException("La etiqueta admite hasta 150 caracteres");
        int sort;
        try{sort=new java.math.BigDecimal(Objects.toString(merged.getOrDefault("Sort_Order",0))).intValueExact();if(sort<0)throw new ArithmeticException();}
        catch(Exception ex){throw new IllegalArgumentException("El orden debe ser un entero mayor o igual a cero");}
        Object active=merged.getOrDefault("Is_Active",true);if(!(active instanceof Boolean))throw new IllegalArgumentException("Estado inválido");
        return new HashMap<>(Map.of("value",value.trim(),"label",text,"sort",sort,"active",active));
    }
    @GetMapping("/users/{userId}/systems/{systemId}/attributes") List<Map<String,Object>> values(@PathVariable String userId,@PathVariable String systemId){requireAccess(userId,systemId);return c.db().queryForList("SELECT a.*,v.Id_User_Attribute_Value,v.Value_Text,v.Value_Integer,v.Value_Decimal,v.Value_Boolean,v.Value_Date,v.Value_Datetime,v.Value_Json FROM system_attributes a LEFT JOIN user_system_attribute_values v ON v.Id_Attribute=a.Id_Attribute AND v.Id_User=:u AND v.Id_System=:s WHERE a.Id_System=:s AND a.Is_Active=TRUE ORDER BY a.Sort_Order",key(userId,systemId)).stream().map(CrudService::formatDates).toList();}
    @PutMapping("/users/{userId}/systems/{systemId}/attributes/{attributeId}") void value(@PathVariable String userId,@PathVariable String systemId,@PathVariable String attributeId,@RequestBody Map<String,Object>b){values.save(userId,systemId,attributeId,b);}
}
