package com.etic.licensecontrol.common;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

@Service
public class CrudService {
    public record Definition(String table,String id,List<String> writable,List<String> required){}
    private final NamedParameterJdbcTemplate db;
    private final InputValidator validator;
    public CrudService(NamedParameterJdbcTemplate db,InputValidator validator){this.db=db;this.validator=validator;}
    public List<Map<String,Object>> list(Definition d,String search,int page,int size,String parentColumn,String parent){
        size=Math.min(Math.max(size,1),100);page=Math.max(page,0);String where="";MapSqlParameterSource p=new MapSqlParameterSource().addValue("limit",size).addValue("offset",page*size);
        List<String> clauses=new ArrayList<>(List.of("Is_Active=TRUE"));if(parentColumn!=null){clauses.add(parentColumn+"=:parent");p.addValue("parent",parent);}if(search!=null&&!search.isBlank()){List<String> q=d.writable.stream().filter(c->c.matches("(?i).*(Code|Name|Username|Email|Status|Action|Type).*" )).map(c->"CAST("+c+" AS CHAR) LIKE :search").toList();if(!q.isEmpty()){clauses.add("("+String.join(" OR ",q)+")");p.addValue("search","%"+search+"%");}}if(!clauses.isEmpty())where=" WHERE "+String.join(" AND ",clauses);
        return db.queryForList("SELECT * FROM "+d.table+where+" ORDER BY "+d.id+" LIMIT :limit OFFSET :offset",p);
    }
    public Map<String,Object> get(Definition d,String id){return db.query("SELECT * FROM "+d.table+" WHERE "+d.id+"=:id AND Is_Active=TRUE",Map.of("id",id),(r,n)->{Map<String,Object> m=new LinkedHashMap<>();var md=r.getMetaData();for(int i=1;i<=md.getColumnCount();i++){String k=md.getColumnLabel(i);if(!"Password_Hash".equals(k))m.put(k,dateValue(r.getObject(i)));}return m;}).stream().findFirst().orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Registro no encontrado"));}
    @Transactional public Map<String,Object> create(Definition d,Map<String,Object> body){
        if(d.writable.contains("Code"))body.put("Code","roles".equals(d.table)?roleCode(body):generatedCode(body.get("Name"),switch(d.table){case "user_types"->50;case "system_attributes"->100;case "permissions"->120;default->80;}));
        validate(d,body);validator.validate(d.table,body);
        String id=UUID.randomUUID().toString();MapSqlParameterSource p=params(d,body).addValue("id",id);
        List<String> cols=d.writable.stream().filter(body::containsKey).toList();
        db.update("INSERT INTO "+d.table+" ("+d.id+(cols.isEmpty()?"":","+String.join(",",cols))+") VALUES (:id"+(cols.isEmpty()?"":",:"+String.join(",:",cols))+")",p);
        audit(d.table,id,"CREATE");return get(d,id);
    }
    public static String generatedCode(Object name,int maxLength){
        String code=java.text.Normalizer.normalize(Objects.toString(name,"").trim(),java.text.Normalizer.Form.NFD)
            .replaceAll("\\p{M}","").toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]+","_").replaceAll("^_|_$","");
        if(code.length()>maxLength)code=code.substring(0,maxLength).replaceAll("_$","");
        if(code.isEmpty())throw new IllegalArgumentException("El nombre debe contener letras o números para generar el código");
        return code;
    }
    private String roleCode(Map<String,Object> body){
        String code=generatedCode(body.get("Name"),80);
        if(db.queryForObject("SELECT COUNT(*) FROM roles WHERE Id_System=:system AND Code=:code",new MapSqlParameterSource().addValue("system",body.get("Id_System")).addValue("code",code),Integer.class)>0)throw new IllegalArgumentException("Ya existe un rol con ese nombre/código en el sistema");
        return code;
    }
    @Transactional public void deactivate(Definition d,String id){get(d,id);db.update("UPDATE "+d.table+" SET Is_Active=FALSE WHERE "+d.id+"=:id",Map.of("id",id));audit(d.table,id,"DEACTIVATE");}
    @Transactional public Map<String,Object> update(Definition d,String id,Map<String,Object> body){if(d.writable.contains("Code"))body.remove("Code");if(d.writable.contains("Value_Code"))body.remove("Value_Code");var original=get(d,id);var merged=new HashMap<>(original);if(original.get("Id_System")!=null&&body.containsKey("Id_System")&&!Objects.equals(body.get("Id_System"),merged.get("Id_System")))throw new IllegalArgumentException("No se puede trasladar un registro existente a otro sistema");merged.putAll(body);validate(d,merged);validator.validate(d.table,merged);for(String k:body.keySet())body.put(k,merged.get(k));List<String> cols=d.writable.stream().filter(body::containsKey).toList();if(cols.isEmpty())throw new IllegalArgumentException("No hay campos para actualizar");db.update("UPDATE "+d.table+" SET "+String.join(",",cols.stream().map(c->c+"=:"+c).toList())+" WHERE "+d.id+"=:id",params(d,body).addValue("id",id));audit(d.table,id,"UPDATE");return get(d,id);}
    private MapSqlParameterSource params(Definition d,Map<String,Object>b){MapSqlParameterSource p=new MapSqlParameterSource();d.writable.forEach(c->{if(b.containsKey(c)){Object v=b.get(c);if(v instanceof String s&&s.isBlank())v=null;p.addValue(c,v);}});return p;}
    private void validate(Definition d,Map<String,Object>b){for(String c:d.required)if(!b.containsKey(c)||b.get(c)==null||b.get(c).toString().isBlank())throw new IllegalArgumentException(c+" es obligatorio");if(b.containsKey("Valid_From")&&b.containsKey("Valid_Until")&&b.get("Valid_From")!=null&&b.get("Valid_Until")!=null&&b.get("Valid_From").toString().compareTo(b.get("Valid_Until").toString())>0)throw new IllegalArgumentException("Valid_Until debe ser posterior a Valid_From");}
    private static Object dateValue(Object value){if(value instanceof java.sql.Timestamp t)return t.toLocalDateTime().toString();if(value instanceof java.sql.Date d)return d.toLocalDate().toString();return value;}
    public static Map<String,Object> formatDates(Map<String,Object> row){row.replaceAll((key,value)->Set.of("Is_Active","Assigned").contains(key)&&value instanceof Number n?n.intValue()!=0:dateValue(value));return row;}
    public NamedParameterJdbcTemplate db(){return db;}
    public void audit(String entity,String id,String action){var auth=org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();Map<String,Object>p=new HashMap<>();p.put("event",UUID.randomUUID().toString());p.put("user",auth==null?null:auth.getName());p.put("entity",entity);p.put("id",id);p.put("action",action);db.update("INSERT INTO audit_events(Id_Audit_Event,Id_User,Id_System,Action,Entity_Type,Entity_Id) SELECT :event,:user,Id_System,:action,:entity,:id FROM systems WHERE Code='LICENSE_CONTROL'",p);}
    public List<Map<String,Object>> filtered(Definition d,String search,int page,int size,Map<String,String> filters,String sort,String direction){
        size=Math.min(Math.max(size,1),100);page=Math.max(page,0);List<String>w=new ArrayList<>(List.of("Is_Active=TRUE"));MapSqlParameterSource p=new MapSqlParameterSource().addValue("size",size).addValue("offset",page*size);
        for(String key:List.of("Status","Id_System","Id_User_Type","Id_User"))if(d.writable.contains(key)&&filters.get(key)!=null&&!filters.get(key).isBlank()){w.add(key+"=:"+key);p.addValue(key,filters.get(key));}
        if(search!=null&&!search.isBlank()){var fields=d.writable.stream().filter(k->k.matches("(?i).*(Code|Name|Username|Email|UUID).*" )).map(k->"CAST("+k+" AS CHAR) LIKE :search").toList();if(!fields.isEmpty()){w.add("("+String.join(" OR ",fields)+")");p.addValue("search","%"+search+"%");}}
        String order=d.writable.contains(sort)||d.id.equals(sort)?sort:d.id;
        var rows=db.queryForList("SELECT * FROM "+d.table+(w.isEmpty()?"":" WHERE "+String.join(" AND ",w))+" ORDER BY "+order+("desc".equalsIgnoreCase(direction)?" DESC":" ASC")+" LIMIT :size OFFSET :offset",p);rows.forEach(r->{r.remove("Password_Hash");formatDates(r);});return rows;
    }
}
