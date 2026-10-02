import java.sql.*;
import java.nio.file.*;
import java.util.*;
public class InspectDatabase {
 public static void main(String[] args)throws Exception {
  Properties p=new Properties();try(var r=Files.newBufferedReader(Path.of("src/main/resources/application-local.properties"),java.nio.charset.StandardCharsets.UTF_8)){p.load(r);}
  String password=System.getenv("SPRING_DATASOURCE_PASSWORD");if(password==null){String s=p.getProperty("spring.datasource.password");password=s.substring(s.indexOf(':')+1,s.length()-1);}
  try(var c=DriverManager.getConnection("jdbc:mysql://127.0.0.1:3307/license_system?allowPublicKeyRetrieval=true&useSSL=false&characterEncoding=UTF-8&connectionCollation=utf8mb4_0900_ai_ci","etic_local",password);var s=c.createStatement()){
   if(args.length>0 && args[0].equals("nullable-version-code")){
    try(var r=s.executeQuery("SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='license_system' AND TABLE_NAME='application_versions' AND COLUMN_NAME='Version_Code'")){r.next();if(r.getString(1).equals("YES")){System.out.println("VERSION_CODE_ALREADY_NULLABLE");return;}}
    s.executeUpdate("ALTER TABLE application_versions MODIFY COLUMN Version_Code BIGINT NULL");System.out.println("VERSION_CODE_NULLABLE_APPLIED");return;
   }
   for(String table:List.of("systems","roles","user_types","system_attributes","system_attribute_options","licensed_applications","application_versions","user_system_attribute_values","user_system_access","users","licensed_devices")){
    try(var r=s.executeQuery("SHOW CREATE TABLE "+table)){r.next();System.out.println(r.getString(2));}
    if(!List.of("users","user_system_attribute_values","user_system_access","application_versions","licensed_devices").contains(table))try(var r=s.executeQuery("SELECT * FROM "+table+" LIMIT 20")){var m=r.getMetaData();while(r.next()){for(int i=1;i<=m.getColumnCount();i++)System.out.print(m.getColumnLabel(i)+"="+r.getString(i)+" | ");System.out.println();}}
   }
  }
 }
}
