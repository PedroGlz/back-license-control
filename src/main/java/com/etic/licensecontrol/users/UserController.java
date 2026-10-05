package com.etic.licensecontrol.users;

import com.etic.licensecontrol.common.CrudService;
import java.time.LocalDateTime;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController @RequestMapping("/api/admin/users")
public class UserController {
    private final CrudService c;private final PasswordEncoder encoder;
    private static final CrudService.Definition D=new CrudService.Definition("users","Id_User",List.of("Id_User_Type","Username","First_Name","Last_Name","Second_Last_Name","Email"),List.of("Id_User_Type","Username","First_Name"));
    UserController(CrudService c,PasswordEncoder encoder){this.c=c;this.encoder=encoder;}
    @DeleteMapping("/{id}") void deactivate(@PathVariable String id){c.deactivate(D,id);}
    @GetMapping List<Map<String,Object>> list(@RequestParam(defaultValue="")String search,@RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="25")int size,@RequestParam Map<String,String> params){return c.filtered(D,search,page,size,params,params.getOrDefault("sort","Username"),params.getOrDefault("direction","asc"));}
    @GetMapping("/{id}") Map<String,Object> get(@PathVariable String id){return safe(c.get(D,id));}
    @PostMapping @Transactional Map<String,Object> create(@RequestBody Map<String,Object>b){Object password=b.remove("Password");if(password==null||password.toString().length()<8||password.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length>72)throw new IllegalArgumentException("Password debe tener al menos 8 caracteres y máximo 72 bytes");b.keySet().retainAll(D.writable());for(String key:List.of("Last_Name","Second_Last_Name","Email"))b.putIfAbsent(key,null);for(String key:D.required())if(b.get(key)==null||b.get(key).toString().isBlank())throw new IllegalArgumentException(key+" es obligatorio");new com.etic.licensecontrol.common.InputValidator(c.db()).validate("users",b);String id=UUID.randomUUID().toString();MapSqlParameterSource p=new MapSqlParameterSource(b).addValue("id",id).addValue("hash",encoder.encode(password.toString()));c.db().update("INSERT INTO users(Id_User,Id_User_Type,Username,Password_Hash,First_Name,Last_Name,Second_Last_Name,Email,Password_Changed_At) VALUES(:id,:Id_User_Type,:Username,:hash,:First_Name,:Last_Name,:Second_Last_Name,:Email,NOW())",p);c.audit("users",id,"CREATE");return get(id);}
    @PutMapping("/{id}") Map<String,Object> update(@PathVariable String id,@RequestBody Map<String,Object>b){b.keySet().retainAll(D.writable());return safe(c.update(D,id,b));}
    @PutMapping("/{id}/password") void password(@PathVariable String id,@RequestBody Map<String,String>b){String p=b.get("password");if(p==null||p.length()<8||p.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>72)throw new IllegalArgumentException("La contraseña debe tener al menos 8 caracteres y máximo 72 bytes");if(c.db().update("UPDATE users SET Password_Hash=:hash,Password_Changed_At=NOW() WHERE Id_User=:id",Map.of("hash",encoder.encode(p),"id",id))==0)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Usuario no encontrado");c.audit("users",id,"PASSWORD_CHANGE");}
    private Map<String,Object> safe(Map<String,Object> m){m.remove("Password_Hash");return m;}
}
