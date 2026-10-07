package com.etic.licensecontrol.common;

import static java.util.List.of;
import java.util.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;

@RestController @RequestMapping("/api/admin")
public class AdminCatalogController {
    private final CrudService crud;
    private static final Map<String,CrudService.Definition> DEFS=Map.ofEntries(
      Map.entry("user-types",new CrudService.Definition("user_types","Id_User_Type",of("Code","Name","Description"),of("Code","Name"))),
      Map.entry("systems",new CrudService.Definition("systems","Id_System",of("Code","Name","System_Type","Description","Package_Name"),of("Code","Name","System_Type"))),
      Map.entry("roles",new CrudService.Definition("roles","Id_Role",of("Id_System","Code","Name","Description","Is_System_Admin"),of("Id_System","Name"))),
      Map.entry("permissions",new CrudService.Definition("permissions","Id_Permission",of("Id_System","Code","Name","Description","Resource_Name","Action_Name"),of("Id_System","Code","Name"))),
      Map.entry("attributes",new CrudService.Definition("system_attributes","Id_Attribute",of("Id_System","Code","Name","Description","Data_Type","Is_Required","Is_Multivalue","Default_Value","Validation_Regex","Min_Value","Max_Value","Sort_Order"),of("Id_System","Code","Name","Data_Type"))),
      Map.entry("devices",new CrudService.Definition("licensed_devices","Id_Device",of("Display_Name","Manufacturer","Model","Android_Version","App_Version","Status","Activated_At","Last_Validation_At"),of()))
    );
    AdminCatalogController(CrudService crud){this.crud=crud;}
    @DeleteMapping("/{resource:user-types|systems|roles|permissions|attributes}/{id}") void deactivate(@PathVariable String resource,@PathVariable String id){crud.deactivate(DEFS.get(resource),id);}
    @GetMapping("/{resource:user-types|systems|roles|permissions|attributes|devices}") List<Map<String,Object>> list(@PathVariable String resource,@RequestParam(defaultValue="")String search,@RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="25")int size,@RequestParam Map<String,String> params){var rows=crud.filtered(DEFS.get(resource),search,page,size,params,params.getOrDefault("sort","Name"),params.getOrDefault("direction","asc"));if("devices".equals(resource))deviceRelations(rows);if("systems".equals(resource))licensing(rows);return rows;}
    @GetMapping("/{resource:user-types|systems|roles|permissions|attributes|devices}/{id}") Map<String,Object> get(@PathVariable String resource,@PathVariable String id){var row=crud.get(DEFS.get(resource),id);if("devices".equals(resource))deviceRelations(List.of(row));if("systems".equals(resource))licensing(List.of(row));return row;}
    @org.springframework.transaction.annotation.Transactional @PostMapping("/{resource:user-types|systems|roles|permissions|attributes}") Map<String,Object> create(@PathVariable String resource,@RequestBody Map<String,Object>b,Authentication auth){boolean supplied=b.containsKey("Licensing_Mode");Object mode=b.remove("Licensing_Mode");Object days=b.remove("Offline_Validity_Days");defaults(resource,b,true);var row=crud.create(DEFS.get(resource),b);if("systems".equals(resource)){saveLicensing(row,mode,supplied,days);licensing(List.of(row));}return row;}
    @org.springframework.transaction.annotation.Transactional @PutMapping("/{resource:user-types|systems|roles|permissions|attributes}/{id}") Map<String,Object> update(@PathVariable String resource,@PathVariable String id,@RequestBody Map<String,Object>b,Authentication auth){if("roles".equals(resource))b.remove("Code");boolean supplied=b.containsKey("Licensing_Mode");Object mode=b.remove("Licensing_Mode");Object days=b.remove("Offline_Validity_Days");defaults(resource,b,false);var row=crud.update(DEFS.get(resource),id,b);if("systems".equals(resource)){saveLicensing(row,mode,supplied,days);licensing(List.of(row));}return row;}
    private void licensing(List<Map<String,Object>> rows){
        if(rows.isEmpty())return;
        var configured=crud.db().queryForList("SELECT Id_System,Licensing_Mode,Offline_Validity_Days FROM system_licensing WHERE Id_System IN (:ids) AND Is_Active=TRUE",Map.of("ids",rows.stream().map(r->r.get("Id_System")).toList()));
        for(var row:rows){row.put("Licensing_Mode",null);for(var config:configured)if(Objects.equals(row.get("Id_System"),config.get("Id_System"))){row.put("Licensing_Mode",config.get("Licensing_Mode"));row.put("Offline_Validity_Days",config.get("Offline_Validity_Days"));}}
    }
    private void saveLicensing(Map<String,Object> row,Object mode,boolean supplied,Object days){
        var params=new org.springframework.jdbc.core.namedparam.MapSqlParameterSource().addValue("system",row.get("Id_System")).addValue("package",row.get("Package_Name"));
        if(!"ANDROID".equals(row.get("System_Type"))){
            if(mode!=null&&!mode.toString().isBlank())throw new IllegalArgumentException("Solo Android admite licenciamiento de dispositivo");
            crud.db().update("UPDATE system_licensing SET Is_Active=FALSE,Modified_At=UTC_TIMESTAMP(6) WHERE Id_System=:system",params);
            crud.db().update("UPDATE systems SET Package_Name=NULL WHERE Id_System=:system",params);row.put("Package_Name",null);return;
        }
        Integer offline=null;
        if(days!=null){try{offline=Integer.valueOf(days.toString());}catch(Exception ex){throw new IllegalArgumentException("Los días offline deben ser un entero");}if(offline<1||offline>365)throw new IllegalArgumentException("Los días offline deben estar entre 1 y 365");}
        params.addValue("days",offline);
        if(!supplied){crud.db().update("UPDATE system_licensing SET Package_Name=:package,Offline_Validity_Days=COALESCE(:days,Offline_Validity_Days),Modified_At=UTC_TIMESTAMP(6) WHERE Id_System=:system",params);return;}
        if(mode==null||mode.toString().isBlank()){crud.db().update("UPDATE system_licensing SET Is_Active=FALSE,Modified_At=UTC_TIMESTAMP(6) WHERE Id_System=:system",params);return;}
        if(!Set.of("USER_DEVICE","DEVICE_ONLY").contains(mode.toString()))throw new IllegalArgumentException("Modalidad de licenciamiento inválida");
        if(row.get("Package_Name")==null||row.get("Package_Name").toString().isBlank())throw new IllegalArgumentException("Package Name es obligatorio para licenciamiento Android");
        params.addValue("mode",mode);
        if(crud.db().queryForObject("SELECT COUNT(*) FROM system_licensing WHERE Id_System=:system",params,Integer.class)>0)
            crud.db().update("UPDATE system_licensing SET Package_Name=:package,Licensing_Mode=:mode,Offline_Validity_Days=COALESCE(:days,Offline_Validity_Days),Is_Active=TRUE,Modified_At=UTC_TIMESTAMP(6) WHERE Id_System=:system",params);
        else crud.db().update("INSERT INTO system_licensing(Id_System,Package_Name,Licensing_Mode,Offline_Validity_Days,Is_Active) VALUES(:system,:package,:mode,COALESCE(:days,7),TRUE)",params);
    }
    private void deviceRelations(List<Map<String,Object>> rows){
        if(rows.isEmpty())return;
        var ids=rows.stream().map(r->r.get("Id_Device")).toList();
        var relations=crud.db().queryForList("SELECT ld.Id_Device,GROUP_CONCAT(DISTINCT s.Name SEPARATOR ', ') AS Associated_Licenses FROM license_devices ld JOIN licenses l ON l.Id_License=ld.Id_License JOIN systems s ON s.Id_System=l.Id_System WHERE ld.Id_Device IN (:ids) GROUP BY ld.Id_Device",Map.of("ids",ids));
        for(var row:rows){row.remove("Public_Key");row.remove("Fingerprint");for(var relation:relations)if(Objects.equals(row.get("Id_Device"),relation.get("Id_Device")))row.putAll(relation);}
    }
    private void defaults(String r,Map<String,Object>b,boolean create){if("systems".equals(r))b.keySet().retainAll(DEFS.get(r).writable());}
}
