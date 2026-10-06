package com.etic.licensecontrol.auth;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController @RequestMapping("/api/auth")
public class AuthController {
    record Login(@NotBlank String username,@NotBlank String password){}
    record SystemLogin(@NotBlank String username,@NotBlank String password,@NotBlank String system){}
    private final AuthRepository repo;private final PasswordEncoder encoder;private final JwtService jwt;
    AuthController(AuthRepository repo,PasswordEncoder encoder,JwtService jwt){this.repo=repo;this.encoder=encoder;this.jwt=jwt;}
    @PostMapping("/login") @Transactional(noRollbackFor=ResponseStatusException.class) Map<String,Object> login(@Valid @RequestBody Login body){return authenticate(body.username(),body.password(),"LICENSE_CONTROL");}
    @PostMapping("/system-login") @Transactional(noRollbackFor=ResponseStatusException.class) Map<String,Object> systemLogin(@Valid @RequestBody SystemLogin body){return authenticate(body.username(),body.password(),body.system());}
    private Map<String,Object> authenticate(String username,String password,String system){
        var user=repo.loginUser(username).orElse(null);
        HttpStatus denied=null;String reason=null;
        if(user==null||!encoder.matches(password,(String)user.get("Password_Hash"))){denied=HttpStatus.UNAUTHORIZED;reason="Usuario o contraseña incorrectos.";}
        else if(!Boolean.TRUE.equals(user.get("Is_Active"))){denied=HttpStatus.FORBIDDEN;reason="El usuario está inactivo.";}
        else if("LOCKED".equals(user.get("Status"))){denied=HttpStatus.FORBIDDEN;reason="El usuario está bloqueado.";}
        else if("SUSPENDED".equals(user.get("Status"))){denied=HttpStatus.FORBIDDEN;reason="El usuario está suspendido.";}
        else if(!repo.isAuthorized((String)user.get("Id_User"),system)){denied=HttpStatus.FORBIDDEN;reason="El usuario no tiene acceso a este sistema.";}
        if(denied!=null){repo.loginEvent(user==null?Map.of("Username",username):user,false,"INVALID_CREDENTIALS_OR_ACCESS",system);throw new ResponseStatusException(denied,reason);}
        var profile=repo.profile((String)user.get("Id_User"),system);
        String token=jwt.create(profile);
        String previous=(String)user.get("Password_Hash");
        if(encoder.upgradeEncoding(previous)&&!repo.upgradePasswordHash((String)user.get("Id_User"),previous,encoder.encode(password))) {
            repo.loginEvent(user,false,"CREDENTIALS_CHANGED_DURING_LOGIN",system);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Credenciales cambiadas; reintente el login");
        }
        repo.loginEvent(user,true,null,system);
        return Map.of("token",token,"user",profile);
    }
    @GetMapping("/me") Map<String,Object> me(Authentication a){return repo.profile(a.getName(),(String)a.getDetails());}
}
