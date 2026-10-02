package com.etic.licensecontrol.config;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class BootstrapAdmin implements ApplicationRunner {
    private final NamedParameterJdbcTemplate db;
    private final PasswordEncoder encoder;
    private final String username,password,email;
    public BootstrapAdmin(NamedParameterJdbcTemplate db,PasswordEncoder encoder,@Value("${license-control.bootstrap.username}")String username,@Value("${license-control.bootstrap.password}")String password,@Value("${license-control.bootstrap.email}")String email){this.db=db;this.encoder=encoder;this.username=username;this.password=password;this.email=email;}
    @Override @Transactional public void run(ApplicationArguments args){
        if(username.isBlank()||password.isBlank()||email.isBlank())return;
        Integer admins=db.queryForObject("SELECT COUNT(*) FROM user_system_roles ur JOIN roles r ON r.Id_Role=ur.Id_Role AND r.Id_System=ur.Id_System JOIN systems s ON s.Id_System=ur.Id_System JOIN users u ON u.Id_User=ur.Id_User JOIN user_system_access a ON a.Id_User=u.Id_User AND a.Id_System=s.Id_System WHERE s.Code='LICENSE_CONTROL' AND s.Status='ACTIVE' AND r.Status='ACTIVE' AND r.Is_System_Admin=1 AND u.Status='ACTIVE' AND a.Status='ACTIVE' AND (a.Valid_From IS NULL OR a.Valid_From<=NOW()) AND (a.Valid_Until IS NULL OR a.Valid_Until>=NOW())",Map.of(),Integer.class);
        if(admins>0)return;
        if(password.length()<8||password.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>72)throw new IllegalStateException("Contraseña bootstrap inválida");
        if(db.queryForObject("SELECT COUNT(*) FROM users WHERE Username=:name",Map.of("name",username),Integer.class)>0)throw new IllegalStateException("El usuario bootstrap ya existe: asigne su acceso administrativo manualmente");
        db.update("INSERT IGNORE INTO user_types(Id_User_Type,Code,Name,Status) VALUES(UUID(),'EMPLOYEE','Empleado','ACTIVE')",Map.of());
        db.update("INSERT IGNORE INTO systems(Id_System,Code,Name,System_Type,Status) VALUES(UUID(),'LICENSE_CONTROL','License Control','WEB','ACTIVE')",Map.of());
        String type=db.queryForObject("SELECT Id_User_Type FROM user_types WHERE Code='EMPLOYEE' AND Status='ACTIVE'",Map.of(),String.class),system=db.queryForObject("SELECT Id_System FROM systems WHERE Code='LICENSE_CONTROL' AND Status='ACTIVE'",Map.of(),String.class);
        db.update("INSERT IGNORE INTO roles(Id_Role,Id_System,Code,Name,Is_System_Admin,Status) VALUES(UUID(),:s,'SUPER_ADMIN','Super Administrador',1,'ACTIVE')",Map.of("s",system));
        String role=db.queryForObject("SELECT Id_Role FROM roles WHERE Id_System=:s AND Code='SUPER_ADMIN' AND Status='ACTIVE' AND Is_System_Admin=1",Map.of("s",system),String.class),user=UUID.randomUUID().toString();
        db.update("INSERT INTO users(Id_User,Id_User_Type,Username,Password_Hash,First_Name,Email,Status,Password_Changed_At) VALUES(:id,:type,:name,:hash,'Administrador',:email,'ACTIVE',NOW())",Map.of("id",user,"type",type,"name",username,"hash",encoder.encode(password),"email",email));
        db.update("INSERT INTO user_system_access(Id_User_System_Access,Id_User,Id_System,Status) VALUES(UUID(),:u,:s,'ACTIVE')",Map.of("u",user,"s",system));
        db.update("INSERT INTO user_system_roles(Id_User,Id_System,Id_Role) VALUES(:u,:s,:r)",Map.of("u",user,"s",system,"r",role));
    }
}
