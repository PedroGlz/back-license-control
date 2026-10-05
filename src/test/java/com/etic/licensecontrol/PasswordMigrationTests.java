package com.etic.licensecontrol;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.MockMvcPrint;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest(properties={"license-control.bootstrap.username=","license-control.bootstrap.password=",
        "debug=false","logging.level.org.springframework=INFO","logging.level.org.springframework.jdbc=INFO"})
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
@Transactional
class PasswordMigrationTests {
    @Autowired MockMvc mvc;
    @Autowired NamedParameterJdbcTemplate db;
    @Autowired PasswordEncoder encoder;
    final JsonMapper json=JsonMapper.builder().build();
    String user,username,password,type;

    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        String secret=UUID.randomUUID().toString()+UUID.randomUUID();
        registry.add("license-control.jwt.secret",()->secret);
    }

    @BeforeEach void seed() {
        user=UUID.randomUUID().toString();
        username="password_test_"+user.substring(0,8);
        password=UUID.randomUUID().toString();
        String system=db.queryForObject("SELECT Id_System FROM systems WHERE Code='LICENSE_CONTROL'",Map.of(),String.class);
        String role=db.queryForObject("SELECT Id_Role FROM roles WHERE Id_System=:s AND Code='SUPER_ADMIN'",Map.of("s",system),String.class);
        type=db.queryForObject("SELECT Id_User_Type FROM user_types WHERE Code='EMPLOYEE'",Map.of(),String.class);
        db.update("INSERT INTO users(Id_User,Id_User_Type,Username,Password_Hash,First_Name,Status) VALUES(:u,:t,:name,:hash,'Prueba','ACTIVE')",
                Map.of("u",user,"t",type,"name",username,"hash",encoder.encode(password)));
        db.update("INSERT INTO user_system_access(Id_User_System_Access,Id_User,Id_System,Status) VALUES(UUID(),:u,:s,'ACTIVE')",Map.of("u",user,"s",system));
        db.update("INSERT INTO user_system_roles(Id_User,Id_System,Id_Role) VALUES(:u,:s,:r)",Map.of("u",user,"s",system,"r",role));
    }

    @ParameterizedTest @EnumSource(BCryptVersion.class)
    void legacyLoginMigratesToArgon2id(BCryptVersion version) throws Exception {
        setHash(new BCryptPasswordEncoder(version).encode(password));
        login(password).andExpect(status().isOk());
        assertArgon2id(hash(user),password);
    }

    @Test void wrongPasswordDoesNotChangeHash() throws Exception {
        String original=new BCryptPasswordEncoder().encode(password);
        setHash(original);
        login(UUID.randomUUID().toString()).andExpect(status().isUnauthorized());
        assertTrue(original.equals(hash(user)),"El login fallido debe conservar el hash");
    }

    @Test void newUserUsesArgon2id() throws Exception {
        String newPassword=UUID.randomUUID().toString();
        String response=mvc.perform(post("/api/admin/users").header("Authorization","Bearer "+token())
                .contentType("application/json").content(json.writeValueAsString(Map.of("Id_User_Type",type,
                        "Username","new_"+username,"First_Name","Prueba","Status","ACTIVE","Password",newPassword))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertArgon2id(hash(json.readTree(response).get("Id_User").asText()),newPassword);
    }

    @Test void passwordChangeUsesArgon2id() throws Exception {
        String newPassword=UUID.randomUUID().toString();
        mvc.perform(put("/api/admin/users/"+user+"/password").header("Authorization","Bearer "+token())
                .contentType("application/json").content(json.writeValueAsString(Map.of("password",newPassword))))
                .andExpect(status().isOk());
        assertArgon2id(hash(user),newPassword);
    }

    @Test void argon2idLoginAndStrictFormats() throws Exception {
        String original=hash(user);
        login(password).andExpect(status().isOk());
        assertTrue(original.equals(hash(user)),"Argon2id no debe rehashearse al login");
        assertArgon2id(original,password);
        for(String unsupported:new String[]{password,"{noop}"+password,"{bcrypt}"+new BCryptPasswordEncoder().encode(password),
                "0".repeat(32),"0".repeat(64),"$argon2i$invalid","$argon2d$invalid"}) {
            assertFalse(encoder.matches(password,unsupported),"Formato no permitido");
        }
    }

    private ResultActions login(String supplied) throws Exception {
        return mvc.perform(post("/api/auth/login").contentType("application/json")
                .content(json.writeValueAsString(Map.of("username",username,"password",supplied))));
    }
    private String token() throws Exception {
        return json.readTree(login(password).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("token").asText();
    }
    private String hash(String id) {
        return db.queryForObject("SELECT Password_Hash FROM users WHERE Id_User=:u",Map.of("u",id),String.class);
    }
    private void setHash(String hash) {
        db.update("UPDATE users SET Password_Hash=:hash WHERE Id_User=:u",Map.of("hash",hash,"u",user));
    }
    private void assertArgon2id(String hash,String supplied) {
        assertTrue(hash.startsWith("$argon2id$v=19$m=19456,t=2,p=1$"),"Se requiere Argon2id con los parámetros acordados");
        assertTrue(hash.length()<=255,"El hash debe caber en VARCHAR(255)");
        assertTrue(encoder.matches(supplied,hash),"Debe validar la contraseña correcta");
    }
}
