package com.etic.licensecontrol.config;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion;

class BcryptCompatibilityTests {
    @Test void configuredEncoderAccepts2yWithoutChangingHash() {
        var encoder = new SecurityConfig().passwordEncoder();
        String password = "Local-compatibility-fixture-123!";
        String hash = new BCryptPasswordEncoder(BCryptVersion.$2Y).encode(password);
        assertTrue(hash.startsWith("$2y$"));
        assertTrue(encoder.matches(password, hash));
        assertFalse(encoder.matches("incorrect-password", hash));
        assertTrue(hash.startsWith("$2y$"));
    }
}
