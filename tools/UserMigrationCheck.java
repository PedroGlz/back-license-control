import java.sql.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Read-only checks; never prints password hashes or database credentials. */
public class UserMigrationCheck {
    public static void main(String[] args) throws Exception {
        Properties p = new Properties();
        try (var reader = Files.newBufferedReader(Path.of("src/main/resources/application-local.properties"), StandardCharsets.UTF_8)) { p.load(reader); }
        String password = System.getenv("SPRING_DATASOURCE_PASSWORD");
        if (password == null) { String value = p.getProperty("spring.datasource.password"); password = value.substring(value.indexOf(':') + 1, value.length() - 1); }
        try (var c = DriverManager.getConnection("jdbc:mysql://127.0.0.1:3307/license_system?allowPublicKeyRetrieval=true&useSSL=false&characterEncoding=UTF-8&connectionCollation=utf8mb4_0900_ai_ci", "etic_local", password)) {
            c.setReadOnly(true);
            if (args[0].equals("snapshot") || args[0].equals("existing-users")) {
                StringBuilder output = new StringBuilder();
                try (var s = c.createStatement(); var tables = s.executeQuery("SELECT TABLE_SCHEMA,TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA IN ('etic_system','license_system') AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_SCHEMA,TABLE_NAME")) {
                    while (tables.next()) {
                        String table = "`" + tables.getString(1) + "`.`" + tables.getString(2) + "`";
                        if (args[0].equals("existing-users") && !table.equals("`license_system`.`users`")) continue;
                        List<String> rows = new ArrayList<>();
                        String filter = args[0].equals("existing-users") ? " d WHERE NOT EXISTS (SELECT 1 FROM etic_system.usuarios s WHERE s.Id_Usuario = d.Id_User)" : "";
                        try (var rs = c.createStatement(); var r = rs.executeQuery("SELECT * FROM " + table + filter)) {
                            int columns = r.getMetaData().getColumnCount();
                            while (r.next()) {
                                StringBuilder row = new StringBuilder();
                                for (int i = 1; i <= columns; i++) { byte[] bytes = r.getBytes(i); row.append(bytes == null ? "NULL" : HexFormat.of().formatHex(bytes)).append('|'); }
                                rows.add(row.toString());
                            }
                        }
                        Collections.sort(rows);
                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        for (String row : rows) digest.update((row + "\n").getBytes(StandardCharsets.UTF_8));
                        output.append(table).append('\t').append(rows.size()).append('\t').append(HexFormat.of().formatHex(digest.digest())).append('\n');
                    }
                }
                if (args.length > 1) Files.writeString(Path.of(args[1]), output.toString(), StandardCharsets.UTF_8);
                else System.out.print(output);
            } else {
                String sql = args[0].equals("query") ? args[1] : Files.readString(Path.of(args[1]), StandardCharsets.UTF_8);
                for (String query : sql.split(";")) {
                    if (query.isBlank()) continue;
                    try (var s = c.createStatement(); var r = s.executeQuery(query)) {
                        System.out.println("QUERY: " + query.strip());
                        var m = r.getMetaData();
                        while (r.next()) {
                            for (int i = 1; i <= m.getColumnCount(); i++) {
                                String label = m.getColumnLabel(i);
                                if (label.equalsIgnoreCase("Password") || label.equalsIgnoreCase("Password_Hash")) throw new IllegalArgumentException("Do not print password hashes");
                                System.out.print(label + "=" + r.getString(i) + " | ");
                            }
                            System.out.println();
                        }
                    }
                }
            }
        }
    }
}
