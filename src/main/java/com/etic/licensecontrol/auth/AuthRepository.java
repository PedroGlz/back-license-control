package com.etic.licensecontrol.auth;

import java.util.*;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class AuthRepository {
    private final NamedParameterJdbcTemplate db;
    AuthRepository(NamedParameterJdbcTemplate db){this.db=db;}
    Optional<Map<String,Object>> loginUser(String username){return db.query("SELECT u.*,ut.Code User_Type FROM users u JOIN user_types ut ON ut.Id_User_Type=u.Id_User_Type WHERE u.Username=:username AND ut.Is_Active=TRUE",Map.of("username",username),(r,n)->{Map<String,Object> m=new LinkedHashMap<>();var md=r.getMetaData();for(int i=1;i<=md.getColumnCount();i++)m.put(md.getColumnLabel(i),r.getObject(i));return m;}).stream().findFirst();}
    boolean isAuthorized(String id){return isAuthorized(id,"LICENSE_CONTROL");}
    boolean upgradePasswordHash(String id,String previous,String replacement){
        return db.update("UPDATE users SET Password_Hash=:replacement WHERE Id_User=:id AND BINARY Password_Hash=BINARY :previous",Map.of("id",id,"previous",previous,"replacement",replacement))==1;
    }
    boolean isAuthorized(String id,String system){Integer n=db.queryForObject("SELECT COUNT(*) FROM users u JOIN user_types ut ON ut.Id_User_Type=u.Id_User_Type AND ut.Is_Active=TRUE JOIN user_system_access usa ON usa.Id_User=u.Id_User JOIN systems s ON s.Id_System=usa.Id_System JOIN user_system_roles usr ON usr.Id_User=u.Id_User AND usr.Id_System=s.Id_System JOIN roles r ON r.Id_Role=usr.Id_Role AND r.Id_System=s.Id_System WHERE u.Id_User=:id AND u.Is_Active=TRUE AND u.Status NOT IN ('SUSPENDED','LOCKED') AND s.Code=:system AND s.Is_Active=TRUE AND usa.Is_Active=TRUE AND usa.Status NOT IN ('SUSPENDED','REVOKED') AND usr.Is_Active=TRUE AND r.Is_Active=TRUE",Map.of("id",id,"system",system),Integer.class);return n!=null&&n>0;}
    Map<String,Object> profile(String id){return profile(id,"LICENSE_CONTROL");}
    Map<String,Object> profile(String id,String system){
        var params=Map.of("id",id,"system",system);
        Map<String,Object> u=db.queryForMap("SELECT u.Id_User id,u.Username username,u.First_Name firstName,u.Last_Name lastName,u.Second_Last_Name secondLastName,u.Email email,ut.Code userType FROM users u JOIN user_types ut ON ut.Id_User_Type=u.Id_User_Type WHERE u.Id_User=:id",params);
        u.put("system",system);
        u.put("roles",db.queryForList("SELECT DISTINCT r.Code FROM roles r JOIN user_system_roles ur ON ur.Id_Role=r.Id_Role AND ur.Id_System=r.Id_System JOIN systems s ON s.Id_System=ur.Id_System WHERE ur.Id_User=:id AND s.Code=:system AND r.Is_Active=TRUE AND ur.Is_Active=TRUE",params,String.class));
        u.put("permissions",db.queryForList("SELECT DISTINCT p.Code FROM permissions p JOIN role_permissions rp ON rp.Id_Permission=p.Id_Permission JOIN user_system_roles ur ON ur.Id_Role=rp.Id_Role JOIN systems s ON s.Id_System=ur.Id_System JOIN roles r ON r.Id_Role=ur.Id_Role AND r.Id_System=s.Id_System WHERE ur.Id_User=:id AND s.Code=:system AND p.Id_System=s.Id_System AND p.Is_Active=TRUE AND rp.Is_Active=TRUE AND r.Is_Active=TRUE AND ur.Is_Active=TRUE",params,String.class));
        Integer admins=db.queryForObject("SELECT COUNT(*) FROM roles r JOIN user_system_roles ur ON ur.Id_Role=r.Id_Role AND ur.Id_System=r.Id_System JOIN systems s ON s.Id_System=r.Id_System WHERE ur.Id_User=:id AND s.Code=:system AND r.Is_Active=TRUE AND ur.Is_Active=TRUE AND r.Is_System_Admin=1",params,Integer.class);
        u.put("systemAdmin",admins!=null&&admins>0);return u;
    }
    void loginEvent(Map<String,Object> u,boolean ok,String reason){loginEvent(u,ok,reason,"LICENSE_CONTROL");}
    void loginEvent(Map<String,Object> u,boolean ok,String reason,String system){if(ok)db.update("UPDATE users SET Last_Login_At=NOW() WHERE Id_User=:id",Map.of("id",u.get("Id_User")));Map<String,Object> p=new HashMap<>();p.put("event",UUID.randomUUID().toString());p.put("uid",u.get("Id_User"));p.put("name",u.getOrDefault("Username",""));p.put("ok",ok);p.put("reason",reason);p.put("system",system);db.update("INSERT INTO authentication_events(Id_Authentication_Event,Id_User,Id_System,Username_Attempted,Event_Type,Success,Failure_Reason,Client_Type) SELECT :event,:uid,s.Id_System,:name,'LOGIN',:ok,:reason,'WEB' FROM systems s WHERE s.Code=:system",p);}
}
