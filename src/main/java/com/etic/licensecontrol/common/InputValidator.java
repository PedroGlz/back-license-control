package com.etic.licensecontrol.common;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class InputValidator {
    private final NamedParameterJdbcTemplate db;
    public InputValidator(NamedParameterJdbcTemplate db) { this.db = db; }

    public void validate(String table, Map<String,Object> body) {validate(table,body,false);}
    public void validate(String table, Map<String,Object> body,boolean preserveLegacyUser) {
        var columns=db.queryForList("SELECT COLUMN_NAME,CHARACTER_MAXIMUM_LENGTH,DATA_TYPE,IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table",Map.of("table",table));
        for(var column:columns){
            String name=(String)column.get("COLUMN_NAME"); if(!body.containsKey(name))continue;
            Object value=body.get(name); if(value instanceof String s && s.isBlank()){value=null;body.put(name,null);}
            if(value==null){if("NO".equals(column.get("IS_NULLABLE")))throw new IllegalArgumentException(name+" es obligatorio");continue;}
            Number length=(Number)column.get("CHARACTER_MAXIMUM_LENGTH");
            if(length!=null&&value.toString().length()>length.longValue())throw new IllegalArgumentException(name+" excede la longitud máxima de "+length);
            String type=column.get("DATA_TYPE").toString();
            try {
                if(type.equals("date"))LocalDate.parse(value.toString());
                if(type.equals("datetime"))LocalDateTime.parse(value.toString().replace(' ','T'));
                if(Set.of("bigint","int","tinyint").contains(type)&&!(value instanceof Boolean))Long.parseLong(value.toString());
                if(type.equals("decimal"))new BigDecimal(value.toString());
            }catch(Exception ex){throw new IllegalArgumentException(name+" tiene un formato inválido");}
        }
        for(var reference:Map.of("Id_User_Type","user_types","Id_System","systems","Id_Attribute","system_attributes").entrySet()){
            Object id=body.get(reference.getKey());
            if(table.equals("users")&&reference.getKey().equals("Id_User_Type")&&id!=null){
                if(db.queryForObject("SELECT COUNT(*) FROM user_types WHERE Id_User_Type=:id AND Is_Active=TRUE AND Status=\'ACTIVE\'",Map.of("id",id),Integer.class)==0)throw new IllegalArgumentException("El tipo de usuario no existe o está inactivo");
                continue;
            }
            if(id!=null&&db.queryForObject("SELECT COUNT(*) FROM "+reference.getValue()+" WHERE "+reference.getKey()+"=:id AND Is_Active=TRUE",Map.of("id",id),Integer.class)==0)throw new IllegalArgumentException(reference.getKey()+" debe referenciar un registro activo");
        }
        if(Set.of("application_versions","user_application_access","licenses").contains(table)&&body.get("Id_System")!=null){
            var configuration=db.queryForList("SELECT sl.Licensing_Mode FROM systems s JOIN system_licensing sl ON sl.Id_System=s.Id_System WHERE s.Id_System=:id AND s.Is_Active=TRUE AND s.Status='ACTIVE' AND sl.Is_Active=TRUE",Map.of("id",body.get("Id_System")));
            if(configuration.isEmpty())throw new IllegalArgumentException("El sistema no tiene licenciamiento activo");
            if("user_application_access".equals(table)&&!"USER_DEVICE".equals(configuration.getFirst().get("Licensing_Mode")))throw new IllegalArgumentException("Las asignaciones de licencia solo aplican a USER_DEVICE");
            if("licenses".equals(table)){
                String mode=Objects.toString(configuration.getFirst().get("Licensing_Mode"),"");
                if("DEVICE_ONLY".equals(mode))throw new IllegalArgumentException("DEVICE_ONLY se administra desde la licencia comercial y se activa mediante código");
                else if("USER_DEVICE".equals(mode)&&(body.get("Id_Usuario")==null||body.get("Id_Usuario").toString().isBlank()))throw new IllegalArgumentException("Esta modalidad requiere un usuario");
                if("USER_DEVICE".equals(mode)&&"ACTIVE".equals(body.get("Status")))validateAssignment(body);
            }
        }
        if("licensed_devices".equals(table)&&"ACTIVE".equals(body.get("Status"))&&body.get("Public_Key")==null)throw new IllegalArgumentException("El dispositivo debe activarse con su clave pública antes de habilitarse");
        Object email=body.get("Email");if(email!=null&&!email.toString().matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+"))throw new IllegalArgumentException("Email inválido");
        dates(body);
        if(body.get("Max_Devices")!=null&&new BigDecimal(body.get("Max_Devices").toString()).compareTo(BigDecimal.ONE)<0)throw new IllegalArgumentException("Max_Devices debe ser mayor a cero");
        if(body.get("Min_Value")!=null&&body.get("Max_Value")!=null&&new BigDecimal(body.get("Min_Value").toString()).compareTo(new BigDecimal(body.get("Max_Value").toString()))>0)throw new IllegalArgumentException("El mínimo no puede exceder al máximo");
        if(body.get("Validation_Regex")!=null)try{java.util.regex.Pattern.compile(body.get("Validation_Regex").toString());}catch(Exception e){throw new IllegalArgumentException("Expresión regular inválida");}
        if(table.equals("user_application_access")||table.equals("licenses")){
            Object user=body.get("Id_Usuario");if(!preserveLegacyUser&&user!=null&&db.queryForObject("SELECT COUNT(*) FROM users WHERE Id_User=:id",Map.of("id",user),Integer.class)==0)throw new IllegalArgumentException("Usuario inválido");
        }
    }
    public static void dates(Map<String,Object> body){Object start=body.get("Valid_From"),end=body.get("Valid_Until");if(start!=null&&end!=null&&start.toString().compareTo(end.toString())>0)throw new IllegalArgumentException("La vigencia final debe ser posterior a la inicial");}
    private void validateAssignment(Map<String,Object> body) {
        var p=new org.springframework.jdbc.core.namedparam.MapSqlParameterSource().addValue("system",body.get("Id_System")).addValue("user",body.get("Id_Usuario")).addValue("device",body.get("Id_Device"));
        var rows=db.queryForList("SELECT a.Valid_From,a.Valid_Until,a.Max_Devices FROM user_application_access a JOIN users u ON u.Id_User=a.Id_Usuario WHERE a.Id_System=:system AND a.Id_Usuario=:user AND a.Is_Active=TRUE AND a.Status='ACTIVE' AND u.Is_Active=TRUE AND u.Status NOT IN ('SUSPENDED','LOCKED') FOR UPDATE",p);
        if(rows.isEmpty())throw new IllegalArgumentException("El usuario requiere una asignación de licencia activa");
        var access=rows.getFirst();
        if(body.get("Valid_From").toString().compareTo(access.get("Valid_From").toString())<0||access.get("Valid_Until")!=null&&body.get("Valid_Until").toString().compareTo(access.get("Valid_Until").toString())>0)throw new IllegalArgumentException("La vigencia debe estar dentro de la asignación de licencia");
        p.addValue("start",body.get("Valid_From")).addValue("end",body.get("Valid_Until"));
        int used=db.queryForObject("SELECT COUNT(DISTINCT Id_Device) FROM licenses WHERE Id_System=:system AND Id_Usuario=:user AND Is_Active=TRUE AND Status='ACTIVE' AND Id_Device<>:device AND Valid_From<=:end AND Valid_Until>=:start",p,Integer.class);
        if(used>=((Number)access.get("Max_Devices")).intValue())throw new IllegalArgumentException("Se alcanzó el máximo de dispositivos de la asignación");
    }
}
