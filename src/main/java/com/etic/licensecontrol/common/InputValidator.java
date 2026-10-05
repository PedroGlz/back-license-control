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
            if(id!=null&&db.queryForObject("SELECT COUNT(*) FROM "+reference.getValue()+" WHERE "+reference.getKey()+"=:id AND Is_Active=TRUE",Map.of("id",id),Integer.class)==0)throw new IllegalArgumentException(reference.getKey()+" debe referenciar un registro activo");
        }
        Object email=body.get("Email");if(email!=null&&!email.toString().matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+"))throw new IllegalArgumentException("Email inválido");
        dates(body);
        if(body.get("Max_Devices")!=null&&new BigDecimal(body.get("Max_Devices").toString()).compareTo(BigDecimal.ONE)<0)throw new IllegalArgumentException("Max_Devices debe ser mayor a cero");
        if(body.get("Offline_Validity_Days")!=null&&new BigDecimal(body.get("Offline_Validity_Days").toString()).signum()<0)throw new IllegalArgumentException("Días offline inválidos");
        if(body.get("Min_Value")!=null&&body.get("Max_Value")!=null&&new BigDecimal(body.get("Min_Value").toString()).compareTo(new BigDecimal(body.get("Max_Value").toString()))>0)throw new IllegalArgumentException("El mínimo no puede exceder al máximo");
        if(body.get("Validation_Regex")!=null)try{java.util.regex.Pattern.compile(body.get("Validation_Regex").toString());}catch(Exception e){throw new IllegalArgumentException("Expresión regular inválida");}
        if(table.equals("user_application_access")||table.equals("licenses")){
            Object user=body.get("Id_Usuario");if(!preserveLegacyUser&&user!=null&&db.queryForObject("SELECT COUNT(*) FROM users WHERE Id_User=:id",Map.of("id",user),Integer.class)==0)throw new IllegalArgumentException("Usuario inválido");
        }
    }
    public static void dates(Map<String,Object> body){Object start=body.get("Valid_From"),end=body.get("Valid_Until");if(start!=null&&end!=null&&start.toString().compareTo(end.toString())>0)throw new IllegalArgumentException("La vigencia final debe ser posterior a la inicial");}
}
