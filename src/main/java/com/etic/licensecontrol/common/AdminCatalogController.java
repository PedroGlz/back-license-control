package com.etic.licensecontrol.common;

import static java.util.List.of;
import java.util.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;

@RestController @RequestMapping("/api/admin")
public class AdminCatalogController {
    private final CrudService crud;
    private static final Map<String,CrudService.Definition> DEFS=Map.ofEntries(
      Map.entry("user-types",new CrudService.Definition("user_types","Id_User_Type",of("Code","Name","Description","Status"),of("Code","Name","Status"))),
      Map.entry("systems",new CrudService.Definition("systems","Id_System",of("Code","Name","System_Type","Description","Base_Url","Package_Name","Supports_Offline","Offline_Validity_Days","Status"),of("Code","Name","System_Type","Status"))),
      Map.entry("roles",new CrudService.Definition("roles","Id_Role",of("Id_System","Code","Name","Description","Is_System_Admin","Status"),of("Id_System","Code","Name","Status"))),
      Map.entry("permissions",new CrudService.Definition("permissions","Id_Permission",of("Id_System","Code","Name","Description","Resource_Name","Action_Name","Status"),of("Id_System","Code","Name","Status"))),
      Map.entry("attributes",new CrudService.Definition("system_attributes","Id_Attribute",of("Id_System","Code","Name","Description","Data_Type","Is_Required","Is_Multivalue","Default_Value","Validation_Regex","Min_Value","Max_Value","Sort_Order","Status"),of("Id_System","Code","Name","Data_Type","Status"))),
      Map.entry("applications",new CrudService.Definition("licensed_applications","Id_Application",of("Code","Name","Package_Name","Licensing_Mode","Status","Created_At","Updated_At","Created_By","Updated_By"),of("Code","Name","Package_Name","Licensing_Mode","Status"))),
      Map.entry("devices",new CrudService.Definition("licensed_devices","Id_Device",of("Device_UUID","Origin","Display_Name","Manufacturer","Model","Android_Version","Android_ID","Package_Name","App_Version","Notes","Status","Registered_At","Updated_At","Updated_By"),of("Origin","Status"))),
      Map.entry("licenses",new CrudService.Definition("licenses","Id_License",of("Id_Application","Id_Device","Id_Usuario","Valid_From","Valid_Until","Status","Created_At","Updated_At","Created_By","Updated_By"),of("Id_Application","Id_Device","Valid_From","Valid_Until","Status"))),
      Map.entry("application-access",new CrudService.Definition("user_application_access","Id_Access",of("Id_Usuario","Id_Application","Status","Valid_From","Valid_Until","Max_Devices","Created_At","Created_By","Modified_At","Modified_By"),of("Id_Usuario","Id_Application","Status","Valid_From","Max_Devices")))
    );
    AdminCatalogController(CrudService crud){this.crud=crud;}
    @GetMapping("/{resource:user-types|systems|roles|permissions|attributes|applications|devices|licenses|application-access}") List<Map<String,Object>> list(@PathVariable String resource,@RequestParam(defaultValue="")String search,@RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="25")int size,@RequestParam Map<String,String> params){var rows=crud.filtered(DEFS.get(resource),search,page,size,params,params.getOrDefault("sort","Name"),params.getOrDefault("direction","asc"));if("devices".equals(resource))deviceRelations(rows);return rows;}
    @GetMapping("/{resource:user-types|systems|roles|permissions|attributes|applications|devices|licenses|application-access}/{id}") Map<String,Object> get(@PathVariable String resource,@PathVariable String id){var row=crud.get(DEFS.get(resource),id);if("devices".equals(resource))deviceRelations(List.of(row));return row;}
    @PostMapping("/{resource:user-types|systems|roles|permissions|attributes|applications|devices|licenses|application-access}") Map<String,Object> create(@PathVariable String resource,@RequestBody Map<String,Object>b,Authentication auth){if(Set.of("application-access","applications","licenses").contains(resource))b.put("Created_By",auth.getName());defaults(resource,b,true);return crud.create(DEFS.get(resource),b);}
    @PutMapping("/{resource:user-types|systems|roles|permissions|attributes|applications|devices|licenses|application-access}/{id}") Map<String,Object> update(@PathVariable String resource,@PathVariable String id,@RequestBody Map<String,Object>b,Authentication auth){if("devices".equals(resource)){b=new HashMap<>(Map.of("Status",Objects.toString(b.get("Status"),"")));b.put("Updated_At",java.time.LocalDateTime.now().toString());b.put("Updated_By",auth.getName());}defaults(resource,b,false);return crud.update(DEFS.get(resource),id,b);}
    private void deviceRelations(List<Map<String,Object>> rows){
        if(rows.isEmpty())return;
        var ids=rows.stream().map(r->r.get("Id_Device")).toList();
        var relations=crud.db().queryForList("SELECT l.Id_Device,GROUP_CONCAT(DISTINCT COALESCE(u.Username,l.Id_Usuario) SEPARATOR ', ') AS Assigned_Users,GROUP_CONCAT(DISTINCT a.Name SEPARATOR ', ') AS Assigned_Applications FROM licenses l LEFT JOIN users u ON u.Id_User=l.Id_Usuario JOIN licensed_applications a ON a.Id_Application=l.Id_Application WHERE l.Id_Device IN (:ids) GROUP BY l.Id_Device",Map.of("ids",ids));
        for(var row:rows){row.remove("Public_Key");for(var relation:relations)if(Objects.equals(row.get("Id_Device"),relation.get("Id_Device")))row.putAll(relation);}
    }
    private void defaults(String r,Map<String,Object>b,boolean create){if(create&&Set.of("applications","licenses","application-access").contains(r)){b.putIfAbsent("Created_At",java.time.LocalDateTime.now().toString());}if(create&&"devices".equals(r)){b.put("Registered_At",java.time.LocalDateTime.now().toString());b.putIfAbsent("Origin","MANUAL");}if("systems".equals(r)&&(Boolean.FALSE.equals(b.get("Supports_Offline"))||Integer.valueOf(0).equals(b.get("Supports_Offline"))))b.put("Offline_Validity_Days",null);if("application-access".equals(r)){Object max=b.get("Max_Devices");if((create&&max==null)||(max!=null&&Integer.parseInt(max.toString())<1))throw new IllegalArgumentException("Max_Devices debe ser mayor a cero");}}
}
