package com.etic.licensecontrol.licensing;

import com.etic.licensecontrol.common.*;
import java.util.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

@RestController @RequestMapping("/api/admin")
public class CommercialController {
    private final LicenseService service;
    private final CrudService crud;
    private final InputValidator validator;
    public CommercialController(LicenseService service,CrudService crud,InputValidator validator) { this.service=service;this.crud=crud;this.validator=validator; }
    @GetMapping("/licenses") List<Map<String,Object>> list(@RequestParam(required=false) String Id_User) { return service.list().stream().filter(r->Id_User==null||Id_User.equals(r.get("Id_User"))).toList(); }
    @GetMapping("/licenses/{id}") Map<String,Object> detail(@PathVariable String id) { return service.detail(id); }
    @PostMapping("/licenses") Map<String,Object> create(@RequestBody Map<String,Object> body,Authentication auth) { return service.create(body,auth.getName()); }
    @PostMapping("/licenses/{id}/status") void status(@PathVariable String id,@RequestBody Map<String,String> body,Authentication auth) { service.status(id,body.getOrDefault("status",""),auth.getName()); }
    @PostMapping("/licenses/{id}/devices") void link(@PathVariable String id,@RequestBody Map<String,String> body,Authentication auth) { service.linkUserDevice(id,body.get("deviceId"),auth.getName()); }
    @PostMapping("/devices/{id}/retire") void retire(@PathVariable String id,@RequestBody Map<String,String> body,Authentication auth) { service.retireDevice(id,body.getOrDefault("reason",""),auth.getName()); }
    @GetMapping("/customers") List<Map<String,Object>> customers() { return crud.db().queryForList("SELECT Id_Customer,Name,Contact_Name,Email,Phone,Is_Active FROM customers ORDER BY Name",Map.of()); }
    @PostMapping("/customers") @Transactional Map<String,Object> createCustomer(@RequestBody Map<String,Object> body) { return saveCustomer(UUID.randomUUID().toString(),body,true); }
    @PutMapping("/customers/{id}") @Transactional Map<String,Object> updateCustomer(@PathVariable String id,@RequestBody Map<String,Object> body) { return saveCustomer(id,body,false); }
    private Map<String,Object> saveCustomer(String id,Map<String,Object> body,boolean create) {
        String name=Objects.toString(body.get("Name"),"").trim();if(name.isEmpty())throw new IllegalArgumentException("El nombre del cliente es obligatorio");
        body.keySet().retainAll(Set.of("Name","Contact_Name","Email","Phone","Is_Active"));body.put("Name",name);body.putIfAbsent("Is_Active",true);validator.validate("customers",body);
        var p=new MapSqlParameterSource().addValue("id",id);for(String key:List.of("Name","Contact_Name","Email","Phone","Is_Active"))p.addValue(key,body.get(key));
        int changed=crud.db().update(create?"INSERT INTO customers(Id_Customer,Name,Contact_Name,Email,Phone,Is_Active) VALUES(:id,:Name,:Contact_Name,:Email,:Phone,:Is_Active)":"UPDATE customers SET Name=:Name,Contact_Name=:Contact_Name,Email=:Email,Phone=:Phone,Is_Active=:Is_Active,Modified_At=UTC_TIMESTAMP(6) WHERE Id_Customer=:id",p);
        if(changed==0&&!create&&crud.db().queryForObject("SELECT COUNT(*) FROM customers WHERE Id_Customer=:id",p,Integer.class)==0)throw new IllegalArgumentException("Cliente no encontrado");
        crud.audit("customers",id,create?"CREATE":"UPDATE");return Map.of("Id_Customer",id);
    }
}
