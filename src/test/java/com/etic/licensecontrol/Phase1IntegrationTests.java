package com.etic.licensecontrol;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest(properties={"license-control.jwt.secret=integration-test-secret-at-least-32-characters","license-control.bootstrap.username=","license-control.bootstrap.password=","debug=false","logging.level.org.springframework=INFO"})
@AutoConfigureMockMvc
@Transactional
class Phase1IntegrationTests {
    @Autowired MockMvc mvc;
    @Autowired NamedParameterJdbcTemplate db;
    @Autowired PasswordEncoder encoder;
    final JsonMapper json=JsonMapper.builder().build();
    String user,username,system,role,type;
    @BeforeEach void seed(){
        user=UUID.randomUUID().toString();username="test_"+user.substring(0,8);
        system=db.queryForObject("SELECT Id_System FROM systems WHERE Code='LICENSE_CONTROL'",Map.of(),String.class);
        role=db.queryForObject("SELECT Id_Role FROM roles WHERE Id_System=:s AND Code='SUPER_ADMIN'",Map.of("s",system),String.class);
        type=db.queryForObject("SELECT Id_User_Type FROM user_types WHERE Code='EMPLOYEE'",Map.of(),String.class);
        db.update("INSERT INTO users(Id_User,Id_User_Type,Username,Password_Hash,First_Name,Status) VALUES(:id,:t,:name,:hash,'Prueba','ACTIVE')",Map.of("id",user,"t",type,"name",username,"hash",encoder.encode("Test-password-123!")));
        db.update("INSERT INTO user_system_access(Id_User_System_Access,Id_User,Id_System,Status) VALUES(UUID(),:u,:s,'ACTIVE')",Map.of("u",user,"s",system));
        db.update("INSERT INTO user_system_roles(Id_User,Id_System,Id_Role) VALUES(:u,:s,:r)",Map.of("u",user,"s",system,"r",role));
    }
    String token()throws Exception{return json.readTree(mvc.perform(post("/api/auth/login").contentType("application/json").content(json.writeValueAsString(Map.of("username",username,"password","Test-password-123!")))).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("token").asText();}
    Map<String,Object> create(String path,Map<String,Object> body)throws Exception{return json.readValue(mvc.perform(post(path).header("Authorization","Bearer "+token()).contentType("application/json").content(json.writeValueAsString(body))).andExpect(status().isOk()).andReturn().getResponse().getContentAsString(),Map.class);}
    void update(String path,Object body)throws Exception{mvc.perform(put(path).header("Authorization","Bearer "+token()).contentType("application/json").content(json.writeValueAsString(body))).andExpect(status().isOk());}
    @Test void loginAndMeReturnRealRolesAndPermissions()throws Exception{String permission=UUID.randomUUID().toString();db.update("INSERT INTO permissions(Id_Permission,Id_System,Code,Name) VALUES(:p,:s,'TEST_REAL_PERMISSION','Prueba')",Map.of("p",permission,"s",system));db.update("INSERT INTO role_permissions(Id_Role,Id_Permission) VALUES(:r,:p)",Map.of("r",role,"p",permission));mvc.perform(get("/api/auth/me").header("Authorization","Bearer "+token())).andExpect(status().isOk()).andExpect(jsonPath("$.roles").isArray()).andExpect(jsonPath("$.permissions").isArray()).andExpect(jsonPath("$.username").value(username)).andExpect(jsonPath("$.Password_Hash").doesNotExist());assertTrue(db.queryForObject("SELECT COUNT(*) FROM authentication_events WHERE Id_User=:u AND Success=1",Map.of("u",user),Integer.class)>0);}
    @Test void wrongPasswordRejected()throws Exception{mvc.perform(post("/api/auth/login").contentType("application/json").content(json.writeValueAsString(Map.of("username",username,"password","wrong-password")))).andExpect(status().isUnauthorized());}
    @Test void inactiveUserRejected()throws Exception{db.update("UPDATE users SET Status='INACTIVE' WHERE Id_User=:u",Map.of("u",user));reject();}
    @Test void inactiveAccessRejected()throws Exception{db.update("UPDATE user_system_access SET Status='INACTIVE' WHERE Id_User=:u",Map.of("u",user));reject();}
    @Test void withoutRoleRejected()throws Exception{String inactive=UUID.randomUUID().toString();db.update("INSERT INTO roles(Id_Role,Id_System,Code,Name,Status) VALUES(:r,:s,:code,'Inactivo','INACTIVE')",Map.of("r",inactive,"s",system,"code","INACTIVE_"+username));db.update("UPDATE user_system_roles SET Id_Role=:r WHERE Id_User=:u",Map.of("u",user,"r",inactive));reject();}
    @Test void expiredAccessRejected()throws Exception{db.update("UPDATE user_system_access SET Valid_Until='2020-01-01' WHERE Id_User=:u",Map.of("u",user));reject();}
    void reject()throws Exception{mvc.perform(post("/api/auth/login").contentType("application/json").content(json.writeValueAsString(Map.of("username",username,"password","Test-password-123!")))).andExpect(status().isUnauthorized());}
    @Test void userCreateEditAndPassword()throws Exception{var u=create("/api/admin/users",Map.of("Id_User_Type",type,"Username","new_"+username,"First_Name","Nuevo","Status","ACTIVE","Password","New-password-123!"));String id=u.get("Id_User").toString();assertFalse(u.containsKey("Password_Hash"));update("/api/admin/users/"+id,Map.of("First_Name","Editado","Email","test@example.test"));update("/api/admin/users/"+id+"/password",Map.of("password","Changed-password-123!"));assertTrue(encoder.matches("Changed-password-123!",db.queryForObject("SELECT Password_Hash FROM users WHERE Id_User=:id",Map.of("id",id),String.class)));}
    @Test void systemRolePermissionWorkflow()throws Exception{var s=create("/api/admin/systems",Map.of("Code","TEST_"+username,"Name","Sistema temporal","System_Type","WEB","Status","ACTIVE"));String sid=s.get("Id_System").toString();update("/api/admin/systems/"+sid,Map.of("Name","Editado"));var r=create("/api/admin/roles",Map.of("Id_System",sid,"Code","TEST_ROLE","Name","Rol","Status","ACTIVE"));var p=create("/api/admin/permissions",Map.of("Id_System",sid,"Code","TEST_READ","Name","Lectura","Status","ACTIVE"));update("/api/admin/roles/"+r.get("Id_Role")+"/permissions",List.of(p.get("Id_Permission")));assertEquals(1,db.queryForObject("SELECT COUNT(*) FROM role_permissions WHERE Id_Role=:r",Map.of("r",r.get("Id_Role")),Integer.class));update("/api/admin/roles/"+r.get("Id_Role")+"/permissions",List.of());}
    @Test void userSystemAndRolesAvoidDuplicates()throws Exception{var s=create("/api/admin/systems",Map.of("Code","ACCESS_"+username,"Name","Acceso","System_Type","WEB","Status","ACTIVE"));String sid=s.get("Id_System").toString();var r=create("/api/admin/roles",Map.of("Id_System",sid,"Code","TEST_ROLE","Name","Rol","Status","ACTIVE"));createAccess(sid);update("/api/admin/users/"+user+"/systems/"+sid+"/roles",List.of(r.get("Id_Role"),r.get("Id_Role")));assertEquals(1,db.queryForObject("SELECT COUNT(*) FROM user_system_roles WHERE Id_User=:u AND Id_System=:s",Map.of("u",user,"s",sid),Integer.class));}
    void createAccess(String sid)throws Exception{update("/api/admin/users/"+user+"/systems/"+sid,Map.of("Status","ACTIVE"));}
    @Test void roleFromAnotherSystemRejected()throws Exception{String sid=db.queryForObject("SELECT Id_System FROM systems WHERE Code='ETIC_PDM_ANDROID'",Map.of(),String.class);createAccess(sid);mvc.perform(put("/api/admin/users/"+user+"/systems/"+sid+"/roles").header("Authorization","Bearer "+token()).contentType("application/json").content(json.writeValueAsString(List.of(role)))).andExpect(status().isBadRequest());}
    @Test void attributeDefinitionOptionsAndUserValues()throws Exception{var a=create("/api/admin/attributes",Map.of("Id_System",system,"Code","ATTR_"+username,"Name","Catálogo","Data_Type","SELECT","Status","ACTIVE"));String id=a.get("Id_Attribute").toString();mvc.perform(post("/api/admin/attributes/"+id+"/options").header("Authorization","Bearer "+token()).contentType("application/json").content(json.writeValueAsString(Map.of("Value_Code","ONE","Display_Name","Uno","Sort_Order",0,"Status","ACTIVE")))).andExpect(status().isOk());update("/api/admin/users/"+user+"/systems/"+system+"/attributes/"+id,Map.of("value","ONE"));assertEquals("ONE",db.queryForObject("SELECT Value_Text FROM user_system_attribute_values WHERE Id_User=:u AND Id_Attribute=:a",Map.of("u",user,"a",id),String.class));mvc.perform(put("/api/admin/users/"+user+"/systems/"+system+"/attributes/"+id).header("Authorization","Bearer "+token()).contentType("application/json").content("{\"value\":\"INVALID\"}")).andExpect(status().isBadRequest());}
    @Test void unauthenticatedAdminReturns401()throws Exception{mvc.perform(get("/api/admin/users")).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.status").value(401));}
    @Test void loginWithoutSystemAccessRejected()throws Exception{db.update("UPDATE user_system_access SET Status='REVOKED' WHERE Id_User=:u",Map.of("u",user));reject();}
    @Test void filteredPaginationAndAuditAreReal()throws Exception{
        mvc.perform(get("/api/admin/users").param("search",username).param("size","1").param("Status","ACTIVE").header("Authorization","Bearer "+token())).andExpect(status().isOk()).andExpect(jsonPath("$[0].Username").value(username)).andExpect(jsonPath("$[0].Password_Hash").doesNotExist());
        mvc.perform(get("/api/admin/audit").param("user",user).param("size","1").header("Authorization","Bearer "+token())).andExpect(status().isOk()).andExpect(jsonPath("$.authentication.length()").value(1));
    }




    @Test void corsPreflightAllowsFrontendOrigin()throws Exception{mvc.perform(options("/api/auth/login").header("Origin","http://localhost:4400").header("Access-Control-Request-Method","POST").header("Access-Control-Request-Headers","content-type")).andExpect(status().isOk()).andExpect(header().string("Access-Control-Allow-Origin","http://localhost:4400"));}
}
