package com.etic.licensecontrol.auth;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

class AuthControllerTests {
    AuthRepository repo; AuthController controller; BCryptPasswordEncoder encoder;
    @BeforeEach void setup(){repo=mock(AuthRepository.class);encoder=new BCryptPasswordEncoder();controller=new AuthController(repo,encoder,new JwtService("testing-secret-with-at-least-thirty-two-characters",3600));}
    Map<String,Object> user(String status){Map<String,Object>u=new HashMap<>();u.put("Id_User","user-1");u.put("Username","admin");u.put("Password_Hash",encoder.encode("correct-password"));u.put("Status",status);return u;}
    @Test void validLoginReturnsJwtAndProfile(){var u=user("ACTIVE");when(repo.loginUser("admin")).thenReturn(Optional.of(u));when(repo.isAuthorized("user-1","LICENSE_CONTROL")).thenReturn(true);when(repo.profile("user-1","LICENSE_CONTROL")).thenReturn(Map.of("id","user-1","username","admin","system","LICENSE_CONTROL","roles",List.of("SUPER_ADMIN"),"permissions",List.of("USERS_READ")));var r=controller.login(new AuthController.Login("admin","correct-password"));assertNotNull(r.get("token"));assertEquals("user-1",((Map<?,?>)r.get("user")).get("id"));verify(repo).loginEvent(u,true,null,"LICENSE_CONTROL");}
    @Test void wrongPasswordIsRejected(){var u=user("ACTIVE");when(repo.loginUser("admin")).thenReturn(Optional.of(u));assertThrows(ResponseStatusException.class,()->controller.login(new AuthController.Login("admin","wrong")));}
    @Test void inactiveUserIsRejected(){var u=user("INACTIVE");when(repo.loginUser("admin")).thenReturn(Optional.of(u));assertThrows(ResponseStatusException.class,()->controller.login(new AuthController.Login("admin","correct-password")));}
    @Test void userWithoutAccessIsRejected(){var u=user("ACTIVE");when(repo.loginUser("admin")).thenReturn(Optional.of(u));when(repo.isAuthorized("user-1","LICENSE_CONTROL")).thenReturn(false);assertThrows(ResponseStatusException.class,()->controller.login(new AuthController.Login("admin","correct-password")));}
    @Test void userWithoutValidRoleIsRejected(){var u=user("ACTIVE");when(repo.loginUser("admin")).thenReturn(Optional.of(u));when(repo.isAuthorized("user-1","LICENSE_CONTROL")).thenReturn(false);assertThrows(ResponseStatusException.class,()->controller.login(new AuthController.Login("admin","correct-password")));verify(repo).isAuthorized("user-1","LICENSE_CONTROL");}
}
