package com.etic.licensecontrol.access;

import com.etic.licensecontrol.common.CrudService;
import java.math.BigDecimal;
import java.time.*;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

@Service
public class AttributeValueService {
    private final CrudService crud;
    private final JsonMapper json=JsonMapper.builder().build();
    public AttributeValueService(CrudService crud){this.crud=crud;}
    @Transactional public void save(String user,String system,String attribute,Map<String,Object> body){
        var db=crud.db();var key=Map.of("u",user,"s",system,"a",attribute);
        if(db.queryForObject("SELECT COUNT(*) FROM user_system_access WHERE Id_User=:u AND Id_System=:s AND Is_Active=TRUE",key,Integer.class)==0)throw new IllegalArgumentException("Asigne primero el sistema al usuario");
        var found=db.queryForList("SELECT * FROM system_attributes WHERE Id_Attribute=:a AND Id_System=:s AND Is_Active=TRUE",key);
        if(found.isEmpty())throw new IllegalArgumentException("Atributo inválido para este sistema");
        var definition=found.getFirst();String type=definition.get("Data_Type").toString();boolean multi=truth(definition.get("Is_Multivalue"))||type.equals("MULTISELECT");
        String column=multi?"Value_Json":switch(type){case"INTEGER"->"Value_Integer";case"DECIMAL"->"Value_Decimal";case"BOOLEAN"->"Value_Boolean";case"DATE"->"Value_Date";case"DATETIME"->"Value_Datetime";case"JSON"->"Value_Json";default->"Value_Text";};
        Object value=body.containsKey("value")?body.get("value"):body.get(column);
        if(value instanceof String s && s.isBlank())value=null;
        if(value==null&&truth(definition.get("Is_Required")))throw new IllegalArgumentException(definition.get("Name")+" es obligatorio");
        if(value!=null){
            try {
                if(multi){if(value instanceof String s)value=json.readValue(s,List.class);if(!(value instanceof List<?>))throw new IllegalArgumentException("Se requiere una lista de valores");for(Object item:(List<?>)value)validateItem(definition,type.equals("MULTISELECT")?"SELECT":type,item);value=json.writeValueAsString(value);}
                else if(type.equals("JSON")){if(value instanceof String s){json.readTree(s);}else value=json.writeValueAsString(value);}
                else {validateItem(definition,type,value);if(type.equals("DATETIME"))value=value.toString().replace('T',' ');}
            }catch(IllegalArgumentException ex){throw ex;}catch(Exception ex){throw new IllegalArgumentException("Valor inválido para "+definition.get("Name"));}
        }
        Map<String,Object> params=new HashMap<>(key);params.put("id",UUID.randomUUID().toString());
        List<String> columns=List.of("Value_Text","Value_Integer","Value_Decimal","Value_Boolean","Value_Date","Value_Datetime","Value_Json");for(String c:columns)params.put(c,c.equals(column)?value:null);
        db.update("INSERT INTO user_system_attribute_values(Id_User_Attribute_Value,Id_User,Id_System,Id_Attribute,"+String.join(",",columns)+") VALUES(:id,:u,:s,:a,:"+String.join(",:",columns)+") ON DUPLICATE KEY UPDATE "+String.join(",",columns.stream().map(c->c+"=VALUES("+c+")").toList()),params);
        crud.audit("user_system_attribute_values",attribute,"UPDATE");
    }
    private void validateItem(Map<String,Object>d,String type,Object value){
        if(value==null)throw new IllegalArgumentException("Valor vacío inválido");String text=value.toString();
        try{switch(type){case"INTEGER"->Long.parseLong(text);case"DECIMAL"->new BigDecimal(text);case"DATE"->LocalDate.parse(text);case"DATETIME"->LocalDateTime.parse(text.replace(' ','T'));case"BOOLEAN"->{if(!Set.of("true","false","0","1").contains(text))throw new IllegalArgumentException();}case"SELECT"->{if(crud.db().queryForObject("SELECT COUNT(*) FROM system_attribute_options WHERE Id_Attribute=:a AND Value_Code=:v AND Is_Active=TRUE",Map.of("a",d.get("Id_Attribute"),"v",text),Integer.class)==0)throw new IllegalArgumentException();}default->{}}}catch(Exception e){throw new IllegalArgumentException("Valor incompatible con "+d.get("Name"));}
        if(d.get("Validation_Regex")!=null&&!text.matches(d.get("Validation_Regex").toString()))throw new IllegalArgumentException("El valor no cumple el formato de "+d.get("Name"));
        if(Set.of("INTEGER","DECIMAL").contains(type)){BigDecimal number=new BigDecimal(text);if(d.get("Min_Value")!=null&&number.compareTo(new BigDecimal(d.get("Min_Value").toString()))<0||d.get("Max_Value")!=null&&number.compareTo(new BigDecimal(d.get("Max_Value").toString()))>0)throw new IllegalArgumentException("Valor fuera del rango permitido");}
    }
    private boolean truth(Object v){return Boolean.TRUE.equals(v)||v instanceof Number n&&n.intValue()!=0;}
}
