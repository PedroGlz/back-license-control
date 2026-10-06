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
      Map.entry("devices",new CrudService.Definition("licensed_devices","Id_Device",of("Device_UUID","Origin","Display_Name","Manufacturer","Model","Android_Version","Android_ID","Package_Name","App_Version","Notes","Status","Registered_At","Updated_At","Updated_By"),of("Display_Name","Origin","Status"))),
      Map.entry("licenses",new CrudService.Definition("licenses","Id_License",of("Id_System","Id_Device","Id_Usuario","Valid_From","Valid_Until","Status","Created_At","Updated_At","Created_By","Updated_By"),of("Id_System","Id_Device","Valid_From","Valid_Until","Status"))),
      Map.entry("application-access",new CrudService.Definition("user_application_access","Id_Access",of("Id_Usuario","Id_System","Status","Valid_From","Valid_Until","Max_Devices","Created_At","Created_By","Modified_At","Modified_By"),of("Id_Usuario","Id_System","Status","Valid_From","Max_Devices")))
    );
    AdminCatalogController(CrudService crud){this.crud=crud;}
    @DeleteMapping("/{resource:user-types|systems|roles|permissions|attributes|devices|licenses|application-access}/{id}") void deactivate(@PathVariable String resource,@PathVariable String id){crud.deactivate(DEFS.get(resource),id);}
    @GetMapping("/{resource:user-types|systems|roles|permissions|attributes|devices|licenses|application-access}") List<Map<String,Object>> list(@PathVariable String resource,@RequestParam(defaultValue="")String search,@RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="25")int size,@RequestParam Map<String,String> params){var rows=crud.filtered(DEFS.get(resource),search,page,size,params,params.getOrDefault("sort","Name"),params.getOrDefault("direction","asc"));if("devices".equals(resource))deviceRelations(rows);if("systems".equals(resource))licensing(rows);return rows;}
    @GetMapping("/{resource:user-types|systems|roles|permissions|attributes|devices|licenses|application-access}/{id}") Map<String,Object> get(@PathVariable String resource,@PathVariable String id){var row=crud.get(DEFS.get(resource),id);if("devices".equals(resource))deviceRelations(List.of(row));if("systems".equals(resource))licensing(List.of(row));return row;}
    @org.springframework.transaction.annotation.Transactional @PostMapping("/{resource:user-types|systems|roles|permissions|attributes|devices|licenses|application-access}") Map<String,Object> create(@PathVariable String resource,@RequestBody Map<String,Object>b,Authentication auth){if(Set.of("application-access","licenses").contains(resource))b.put("Created_By",auth.getName());boolean supplied=b.containsKey("Licensing_Mode");Object mode=b.remove("Licensing_Mode");defaults(resource,b,true);var row=crud.create(DEFS.get(resource),b);if("systems".equals(resource)){saveLicensing(row,mode,supplied);licensing(List.of(row));}return row;}
    @org.springframework.transaction.annotation.Transactional @PutMapping("/{resource:user-types|systems|roles|permissions|attributes|devices|licenses|application-access}/{id}") Map<String,Object> update(@PathVariable String resource,@PathVariable String id,@RequestBody Map<String,Object>b,Authentication auth){if("roles".equals(resource))b.remove("Code");if("devices".equals(resource)){b.keySet().retainAll(Set.of("Display_Name","Manufacturer","Model","Android_Version","Notes","Status"));b.put("Updated_At",java.time.LocalDateTime.now().toString());b.put("Updated_By",auth.getName());}boolean supplied=b.containsKey("Licensing_Mode");Object mode=b.remove("Licensing_Mode");defaults(resource,b,false);var row=crud.update(DEFS.get(resource),id,b);if("systems".equals(resource)){saveLicensing(row,mode,supplied);licensing(List.of(row));}return row;}
    private void licensing(List<Map<String,Object>> rows){
        if(rows.isEmpty())return;
        var configured=crud.db().queryForList("SELECT Id_System,Licensing_Mode FROM system_licensing WHERE Id_System IN (:ids) AND Is_Active=TRUE",Map.of("ids",rows.stream().map(r->r.get("Id_System")).toList()));
        for(var row:rows){row.put("Licensing_Mode",null);for(var config:configured)if(Objects.equals(row.get("Id_System"),config.get("Id_System")))row.put("Licensing_Mode",config.get("Licensing_Mode"));}
    }
    private void saveLicensing(Map<String,Object> row,Object mode,boolean supplied){
        var params=new org.springframework.jdbc.core.namedparam.MapSqlParameterSource().addValue("system",row.get("Id_System")).addValue("package",row.get("Package_Name"));
        if(!supplied){crud.db().update("UPDATE system_licensing SET Package_Name=:package WHERE Id_System=:system",params);return;}
        if(mode==null||mode.toString().isBlank()){crud.db().update("UPDATE system_licensing SET Is_Active=FALSE,Package_Name=:package WHERE Id_System=:system",params);return;}
        if(!Set.of("USER_DEVICE","DEVICE_ONLY").contains(mode.toString()))throw new IllegalArgumentException("Modalidad de licenciamiento inválida");
        params.addValue("mode",mode);
        crud.db().update("INSERT INTO system_licensing(Id_System,Package_Name,Licensing_Mode,Is_Active) VALUES(:system,:package,:mode,TRUE) ON DUPLICATE KEY UPDATE Package_Name=:package,Licensing_Mode=:mode,Is_Active=TRUE",params);
    }
    private void deviceRelations(List<Map<String,Object>> rows){
        if(rows.isEmpty())return;
        var ids=rows.stream().map(r->r.get("Id_Device")).toList();
        var relations=crud.db().queryForList("SELECT l.Id_Device,GROUP_CONCAT(DISTINCT COALESCE(u.Username,l.Id_Usuario) SEPARATOR ', ') AS Assigned_Users,GROUP_CONCAT(DISTINCT a.Name SEPARATOR ', ') AS Assigned_Applications FROM licenses l LEFT JOIN users u ON u.Id_User=l.Id_Usuario JOIN systems a ON a.Id_System=l.Id_System WHERE l.Is_Active=TRUE AND a.Is_Active=TRUE AND l.Id_Device IN (:ids) GROUP BY l.Id_Device",Map.of("ids",ids));
        for(var row:rows){row.remove("Public_Key");for(var relation:relations)if(Objects.equals(row.get("Id_Device"),relation.get("Id_Device")))row.putAll(relation);}
    }
    private void defaults(String r,Map<String,Object>b,boolean create){if("systems".equals(r))b.keySet().retainAll(DEFS.get(r).writable());if(create&&Set.of("licenses","application-access").contains(r)){b.putIfAbsent("Created_At",java.time.LocalDateTime.now().toString());}if(create&&"devices".equals(r)){b.keySet().retainAll(Set.of("Display_Name","Manufacturer","Model","Android_Version","Notes","Status"));b.put("Registered_At",java.time.LocalDateTime.now().toString());b.put("Origin","MANUAL");b.putIfAbsent("Status","PENDING");if(!Set.of("PENDING","SUSPENDED").contains(b.get("Status")))throw new IllegalArgumentException("El estado inicial debe ser PENDING o SUSPENDED");}if("application-access".equals(r)){Object max=b.get("Max_Devices");if((create&&max==null)||(max!=null&&Integer.parseInt(max.toString())<1))throw new IllegalArgumentException("Max_Devices debe ser mayor a cero");}}
}
