package com.etic.licensecontrol.config;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/** Argon2id para escritura; únicamente Argon2id y BCrypt para lectura. */
public final class MigrationPasswordEncoder implements PasswordEncoder {
    private final PasswordEncoder argon2 = new Argon2PasswordEncoder(16, 32, 1, 19 * 1024, 2);
    private final PasswordEncoder bcrypt = new BCryptPasswordEncoder();

    @Override public String encode(CharSequence rawPassword) { return argon2.encode(rawPassword); }

    @Override public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) return false;
        try {
            if (encodedPassword.startsWith("$argon2id$")) return argon2.matches(rawPassword, encodedPassword);
            if (isBcrypt(encodedPassword)) return bcrypt.matches(rawPassword, encodedPassword);
            return false;
        } catch (IllegalArgumentException e) { return false; }
    }

    @Override public boolean upgradeEncoding(String encodedPassword) { return isBcrypt(encodedPassword); }

    private boolean isBcrypt(String hash) {
        return hash != null && hash.matches("\\A\\$2[aby]\\$(0[4-9]|[12][0-9]|3[01])\\$[./A-Za-z0-9]{53}\\z");
    }
}
