package com.etic.licensecontrol.config;
import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
@SpringBootTest(properties={"license-control.jwt.secret=bootstrap-test-secret-with-at-least-32-characters","license-control.bootstrap.username=","debug=false","logging.level.org.springframework=INFO"})
@Transactional
class BootstrapAdminTests {
 @Autowired NamedParameterJdbcTemplate db;@Autowired PasswordEncoder encoder;
 @Test void bootstrapCreatesOneAdminAndIsIdempotent() {
  db.update("UPDATE user_system_access a JOIN systems s ON s.Id_System=a.Id_System SET a.Status='INACTIVE' WHERE s.Code='LICENSE_CONTROL'",Map.of());
  String name="bootstrap_test_"+UUID.randomUUID().toString().substring(0,8);
  BootstrapAdmin runner=new BootstrapAdmin(db,encoder,name,"Bootstrap-test-pass-123!",name+"@example.test");
  runner.run(null);runner.run(null);
  assertEquals(1,db.queryForObject("SELECT COUNT(*) FROM users WHERE Username=:u",Map.of("u",name),Integer.class));
  assertTrue(encoder.matches("Bootstrap-test-pass-123!",db.queryForObject("SELECT Password_Hash FROM users WHERE Username=:u",Map.of("u",name),String.class)));
  assertEquals(1,db.queryForObject("SELECT COUNT(*) FROM users u JOIN user_system_access a ON a.Id_User=u.Id_User JOIN user_system_roles ur ON ur.Id_User=u.Id_User AND ur.Id_System=a.Id_System JOIN roles r ON r.Id_Role=ur.Id_Role WHERE u.Username=:u AND a.Status='ACTIVE' AND r.Code='SUPER_ADMIN'",Map.of("u",name),Integer.class));
 }
}
