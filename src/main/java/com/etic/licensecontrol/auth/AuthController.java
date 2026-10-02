package com.etic.licensecontrol.auth;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController @RequestMapping("/api/auth")
public class AuthController {
    record Login(@NotBlank String username,@NotBlank String password){}
    private final AuthRepository repo;private final PasswordEncoder encoder;private final JwtService jwt;
    AuthController(AuthRepository repo,PasswordEncoder encoder,JwtService jwt){this.repo=repo;this.encoder=encoder;this.jwt=jwt;}
    @PostMapping("/login") Map<String,Object> login(@Valid @RequestBody Login body){var user=repo.loginUser(body.username()).orElse(null);boolean valid=user!=null&&"ACTIVE".equals(user.get("Status"))&&encoder.matches(body.password(),(String)user.get("Password_Hash"))&&repo.isAuthorized((String)user.get("Id_User"));if(!valid){repo.loginEvent(user==null?Map.of("Username",body.username()):user,false,"INVALID_CREDENTIALS_OR_ACCESS");throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Credenciales o acceso inválidos");}repo.loginEvent(user,true,null);return Map.of("token",jwt.create((String)user.get("Id_User")),"user",repo.profile((String)user.get("Id_User")));}
    @GetMapping("/me") Map<String,Object> me(Authentication a){return repo.profile(a.getName());}
}
