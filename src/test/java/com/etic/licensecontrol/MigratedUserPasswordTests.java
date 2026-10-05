package com.etic.licensecontrol;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest(properties = {
    "license-control.jwt.secret=integration-test-secret-at-least-32-characters",
    "license-control.bootstrap.username=", "license-control.bootstrap.password=",
    "debug=false", "logging.level.org.springframework=INFO"
})
class MigratedUserPasswordTests {
    @Autowired NamedParameterJdbcTemplate db;
    @Autowired PasswordEncoder encoder;

    @Test void verifiesKnownLocalPasswordAgainstUnchangedMigratedHash() {
        String username = System.getenv("PHASE2A_TEST_USERNAME");
        String password = System.getenv("PHASE2A_TEST_PASSWORD");
        assumeTrue(username != null && password != null && !password.isEmpty(),
                "Requiere credenciales conocidas de prueba local; no adivinar passwords.");
        var parameters = Map.of("username", username);
        String hash = db.queryForObject("""
                SELECT d.Password_Hash FROM users d
                JOIN etic_system.usuarios s ON BINARY s.Id_Usuario = BINARY d.Id_User
                WHERE d.Username = :username AND BINARY d.Password_Hash = BINARY s.Password
                """, parameters, String.class);
        assertNotNull(hash, "Debe existir una identidad copiada con hash intacto");
        assertTrue(encoder.matches(password, hash), "PasswordEncoder debe verificar la contraseña local conocida");
    }
}
