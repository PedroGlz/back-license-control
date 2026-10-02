import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.*;
import java.util.*;

public class Utf8MysqlCheck {
    static final String OPTIONS="useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=America/Mexico_City&characterEncoding=UTF-8&connectionCollation=utf8mb4_0900_ai_ci";
    static String quote(String name){return "`"+name.replace("`","``")+"`";}
    static Connection connect(String schema)throws Exception{
        Properties local=new Properties();
        try(var reader=Files.newBufferedReader(Path.of("src/main/resources/application-local.properties"),StandardCharsets.UTF_8)){local.load(reader);}
        String password=System.getenv("SPRING_DATASOURCE_PASSWORD");
        if(password==null){String configured=local.getProperty("spring.datasource.password");password=configured.substring(configured.indexOf(':')+1,configured.length()-1);}
        String user=System.getenv("SPRING_DATASOURCE_USERNAME");if(user==null)user="etic_local";
        return DriverManager.getConnection("jdbc:mysql://127.0.0.1:3307/"+schema+"?"+OPTIONS,user,password);
    }
    static List<String> tables(Connection c)throws Exception{
        var out=new ArrayList<String>();
        try(var s=c.prepareStatement("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME");var r=s.executeQuery()){while(r.next())out.add(r.getString(1));}return out;
    }
    static Map<String,Object> snapshot()throws Exception{
        Map<String,Object> out=new LinkedHashMap<>();
        for(String schema:List.of("etic_system","license_system"))try(var c=connect(schema)){
            for(String table:tables(c))try(var s=c.createStatement();var r=s.executeQuery("SELECT COUNT(*) FROM "+quote(table))){r.next();out.put(schema+"."+table,r.getLong(1));}
        }return out;
    }
    static List<Map<String,Object>> scan()throws Exception{
        var findings=new ArrayList<Map<String,Object>>();
        for(String schema:List.of("etic_system","license_system"))try(var c=connect(schema)){
            for(String table:tables(c)){
                var columns=new ArrayList<String>();var keys=new ArrayList<String>();
                try(var s=c.prepareStatement("SELECT COLUMN_NAME,DATA_TYPE,COLUMN_KEY FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY ORDINAL_POSITION")){
                    s.setString(1,table);try(var r=s.executeQuery()){while(r.next()){
                        String name=r.getString(1),type=r.getString(2);
                        if("PRI".equals(r.getString(3)))keys.add(name);
                        if(Set.of("char","varchar","tinytext","text","mediumtext","longtext","enum","set","json").contains(type)&&!name.matches("(?i).*(password|secret|token|private.key|public.key).*"))columns.add(name);
                    }}
                }
                for(String column:columns){
                    String selected=keys.stream().map(Utf8MysqlCheck::quote).reduce((a,b)->a+","+b).map(x->x+",").orElse("");
                    String cast="CAST("+quote(column)+" AS CHAR CHARACTER SET utf8mb4)";
                    try(var s=c.prepareStatement("SELECT "+selected+cast+" value,HEX("+quote(column)+") hex_value FROM "+quote(table)+" WHERE LOCATE(?, "+cast+")>0 OR LOCATE(?, "+cast+")>0 OR LOCATE(?, "+cast+")>0 OR LOCATE(?, "+cast+")>0")){
                        s.setString(1,"??");s.setString(2,"Ã");s.setString(3,"Â");s.setString(4,"�");
                        try(var r=s.executeQuery()){while(r.next()){
                            Map<String,Object> finding=new LinkedHashMap<>(),pk=new LinkedHashMap<>();
                            for(String key:keys)pk.put(key,r.getString(key));
                            finding.put("schema",schema);finding.put("table",table);finding.put("column",column);finding.put("key",pk);
                            finding.put("value",r.getString("value"));finding.put("hex",r.getString("hex_value"));findings.add(finding);
                        }}
                    }
                }
            }
        }return findings;
    }
    static Map<String,Object> validate()throws Exception{
        Map<String,Object> out=new LinkedHashMap<>();
        for(String schema:List.of("etic_system","license_system"))try(var c=connect(schema);var s=c.createStatement();var r=s.executeQuery("SELECT @@character_set_server server_charset,@@collation_server server_collation,@@character_set_database database_charset,@@collation_database database_collation,@@character_set_client client_charset,@@character_set_connection connection_charset,@@character_set_results results_charset,@@collation_connection connection_collation")){
            r.next();Map<String,Object> vars=new LinkedHashMap<>();for(int i=1;i<=r.getMetaData().getColumnCount();i++){String key=r.getMetaData().getColumnLabel(i),value=r.getString(i);vars.put(key,value);String expected=key.endsWith("collation")?"utf8mb4_0900_ai_ci":"utf8mb4";if(!expected.equals(value)&&!(key.equals("results_charset")&&value==null))throw new IllegalStateException(schema+"."+key+"="+value);}out.put(schema,vars);
        }
        String text="Prueba de aplicación, operación, certificación, información, año, niño.";
        String all="á é í ó ú ñ Á É Í Ó Ú Ñ ¿ ¡ 😀";
        String id=UUID.randomUUID().toString(),code="UTF8_TEST_"+id.substring(0,8);
        try(var c=connect("license_system")){
            c.setAutoCommit(false);
            try{
                try(var s=c.prepareStatement("INSERT INTO systems(Id_System,Code,Name,System_Type,Description,Status) VALUES(?,?,?,'OTHER',?,'INACTIVE')")){s.setString(1,id);s.setString(2,code);s.setString(3,all);s.setString(4,text);s.executeUpdate();}
                try(var s=c.prepareStatement("SELECT Name,Description,HEX(Description) FROM systems WHERE Id_System=?")){s.setString(1,id);try(var r=s.executeQuery()){r.next();String hex=r.getString(3);if(!text.equals(r.getString(2))||!all.equals(r.getString(1))||hex.contains("3F")||!hex.contains("C3B3")||!hex.contains("C3B1"))throw new IllegalStateException("UTF-8 roundtrip failed");out.put("writeRead",Map.of("id",id,"text",r.getString(2),"characters",r.getString(1),"hex",hex,"noReplacement3F",true));}}
                try(var s=c.prepareStatement("DELETE FROM systems WHERE Id_System=? AND Code=?")){s.setString(1,id);s.setString(2,code);if(s.executeUpdate()!=1)throw new IllegalStateException("Temporary row cleanup failed");}
                c.commit();
                try(var s=c.prepareStatement("SELECT COUNT(*) FROM systems WHERE Id_System=?")){s.setString(1,id);try(var r=s.executeQuery()){r.next();if(r.getInt(1)!=0)throw new IllegalStateException("Temporary row remains");}}
                out.put("temporaryRowRemoved",true);
            }catch(Exception e){c.rollback();throw e;}
        }
        return out;
    }
    static String json(Object value){
        if(value==null)return "null";
        if(value instanceof Number||value instanceof Boolean)return value.toString();
        if(value instanceof Map<?,?> m){var items=new ArrayList<String>();m.forEach((k,v)->items.add(json(k.toString())+":"+json(v)));return "{"+String.join(",",items)+"}";}
        if(value instanceof Collection<?> list)return "["+String.join(",",list.stream().map(Utf8MysqlCheck::json).toList())+"]";
        return "\""+value.toString().replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")+"\"";
    }
    public static void main(String[] args)throws Exception{
        Object result=switch(args.length==0?"validate":args[0]){case "snapshot"->snapshot();case "scan"->scan();case "validate"->validate();default->throw new IllegalArgumentException("snapshot, scan or validate");};
        if(args.length>1){
            Path report=Path.of(args[1]).toAbsolutePath().normalize();
            Path root=Path.of("..").toAbsolutePath().normalize();
            if(!report.startsWith(root.resolve("database")))throw new IllegalArgumentException("Report must stay in LICENSE-CONTROL/database");
            Files.writeString(report,json(result),StandardCharsets.UTF_8);
            if(result instanceof List<?> entries){Map<String,Object> counts=new TreeMap<>();for(Object entry:entries){var row=(Map<?,?>)entry;String key=row.get("schema")+"."+row.get("table")+"."+row.get("column");counts.put(key,((Number)counts.getOrDefault(key,0)).intValue()+1);}result=Map.of("report",report.toString(),"count",entries.size(),"counts",counts,"licenseSystem",entries.stream().filter(entry->"license_system".equals(((Map<?,?>)entry).get("schema"))).toList());}
        }
        System.out.println(json(result));
    }
}
