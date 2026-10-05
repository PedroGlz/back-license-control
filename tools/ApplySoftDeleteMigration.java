import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.*;
import java.util.Properties;

/** Ejecuta exclusivamente la migración incremental de License Control local. */
public class ApplySoftDeleteMigration {
    public static void main(String[] args) throws Exception {
        Properties properties = new Properties();
        try (var reader = Files.newBufferedReader(Path.of("src/main/resources/application-local.properties"), StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        String password = System.getenv("SPRING_DATASOURCE_PASSWORD");
        if (password == null) {
            String value = properties.getProperty("spring.datasource.password");
            password = value.substring(value.indexOf(':') + 1, value.length() - 1);
        }
        String sql = Files.readString(Path.of("../database/standardize_soft_delete.sql"), StandardCharsets.UTF_8);
        sql = sql.replaceAll("(?m)^--.*$", "");
        if (sql.matches("(?is).*(\\bDELETE\\s+FROM\\b|\\bDROP\\b|etic_system).*")) throw new IllegalArgumentException("SQL fuera de alcance");
        try (var connection = DriverManager.getConnection("jdbc:mysql://127.0.0.1:3307/license_system?allowPublicKeyRetrieval=true&useSSL=false&characterEncoding=UTF-8", "etic_local", password)) {
            if (!"license_system".equals(connection.getCatalog())) throw new IllegalStateException("Base incorrecta");
            int count = 0;
            for (String statement : sql.split(";")) {
                if (statement.isBlank()) continue;
                try (var command = connection.createStatement()) { command.execute(statement); }
                count++;
            }
            System.out.println("Migración License Control completada: " + count + " sentencias. Sin eliminación de datos.");
        }
    }
}
