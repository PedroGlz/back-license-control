package com.etic.licensecontrol.config;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class BootstrapAdmin implements ApplicationRunner {
    private static final Logger log=LoggerFactory.getLogger(BootstrapAdmin.class);
    private final NamedParameterJdbcTemplate db;
    private final PasswordEncoder encoder;
    private final String username,password,email;

    public BootstrapAdmin(NamedParameterJdbcTemplate db,PasswordEncoder encoder,
            @Value("${license-control.bootstrap.username}") String username,
            @Value("${license-control.bootstrap.password}") String password,
            @Value("${license-control.bootstrap.email}") String email) {
        this.db=db;this.encoder=encoder;this.username=username;this.password=password;this.email=email;
    }

    @Override @Transactional
    public void run(ApplicationArguments args) {
        if(username.isBlank()||password.isBlank()||email.isBlank())return;
        if(functionalAdminExists()){
            log.info("Bootstrap admin already configured.");
            return;
        }

        String type=ensureUserType();
        String system=ensureSystem();
        String role=ensureRole(system);
        String user=findUser();
        if(user==null)user=createUser(type);
        ensureAccess(user,system);
        ensureRoleAssignment(user,system,role);
        log.info("Bootstrap admin access reconciled.");
    }

    private boolean functionalAdminExists() {
        Integer count=db.queryForObject("SELECT COUNT(*) FROM user_system_roles ur JOIN roles r ON r.Id_Role=ur.Id_Role AND r.Id_System=ur.Id_System JOIN systems s ON s.Id_System=ur.Id_System JOIN users u ON u.Id_User=ur.Id_User JOIN user_system_access a ON a.Id_User=u.Id_User AND a.Id_System=s.Id_System WHERE s.Code='LICENSE_CONTROL' AND s.Is_Active=TRUE AND s.Status='ACTIVE' AND r.Is_Active=TRUE AND r.Status='ACTIVE' AND ur.Is_Active=TRUE AND r.Is_System_Admin=TRUE AND u.Is_Active=TRUE AND u.Status='ACTIVE' AND a.Is_Active=TRUE AND a.Status='ACTIVE'",Map.of(),Integer.class);
        return count!=null&&count>0;
    }

    private String ensureUserType() {
        db.update("INSERT INTO user_types(Id_User_Type,Code,Name) VALUES(:id,'EMPLOYEE','Empleado') ON DUPLICATE KEY UPDATE Is_Active=TRUE,Status='ACTIVE'",Map.of("id",UUID.randomUUID().toString()));
        return db.queryForObject("SELECT Id_User_Type FROM user_types WHERE Code='EMPLOYEE'",Map.of(),String.class);
    }

    private String ensureSystem() {
        db.update("INSERT INTO systems(Id_System,Code,Name,System_Type) VALUES(:id,'LICENSE_CONTROL','License Control','WEB') ON DUPLICATE KEY UPDATE Is_Active=TRUE,Status='ACTIVE'",Map.of("id",UUID.randomUUID().toString()));
        return db.queryForObject("SELECT Id_System FROM systems WHERE Code='LICENSE_CONTROL'",Map.of(),String.class);
    }

    private String ensureRole(String system) {
        db.update("INSERT INTO roles(Id_Role,Id_System,Code,Name,Is_System_Admin) VALUES(:id,:system,'SUPER_ADMIN','Super Administrador',TRUE) ON DUPLICATE KEY UPDATE Name='Super Administrador',Is_System_Admin=TRUE,Is_Active=TRUE,Status='ACTIVE'",Map.of("id",UUID.randomUUID().toString(),"system",system));
        return db.queryForObject("SELECT Id_Role FROM roles WHERE Id_System=:system AND Code='SUPER_ADMIN'",Map.of("system",system),String.class);
    }

    private String findUser() {
        List<String> users=db.queryForList("SELECT Id_User FROM users WHERE Username=:username",Map.of("username",username),String.class);
        return users.isEmpty()?null:users.getFirst();
    }

    private String createUser(String type) {
        if(password.length()<8||password.getBytes(StandardCharsets.UTF_8).length>72)throw new IllegalStateException("Contraseña bootstrap inválida");
        String user=UUID.randomUUID().toString();
        db.update("INSERT INTO users(Id_User,Id_User_Type,Username,Password_Hash,First_Name,Email,Password_Changed_At) VALUES(:id,:type,:username,:hash,'Administrador',:email,NOW())",Map.of("id",user,"type",type,"username",username,"hash",encoder.encode(password),"email",email));
        return user;
    }

    private void ensureAccess(String user,String system) {
        db.update("INSERT INTO user_system_access(Id_User_System_Access,Id_User,Id_System) VALUES(:id,:user,:system) ON DUPLICATE KEY UPDATE Is_Active=TRUE,Status='ACTIVE'",Map.of("id",UUID.randomUUID().toString(),"user",user,"system",system));
    }

    private void ensureRoleAssignment(String user,String system,String role) {
        db.update("INSERT INTO user_system_roles(Id_User,Id_System,Id_Role) VALUES(:user,:system,:role) ON DUPLICATE KEY UPDATE Is_Active=TRUE",Map.of("user",user,"system",system,"role",role));
    }
}
