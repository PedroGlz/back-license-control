package com.etic.licensecontrol.licensing;

import jakarta.mail.internet.InternetAddress;
import java.nio.file.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class MailConfigurationService {
    public record Delivery(List<String> cc, List<String> bcc, Guide guide) {}
    public record RecipientCopies(List<String> cc, List<String> bcc) {}
    public record Guide(String originalName, Path path) {}

    private final NamedParameterJdbcTemplate db;
    private final Path guideStorage;

    public MailConfigurationService(NamedParameterJdbcTemplate db,
            @Value("${license-control.storage.path}") String storagePath) {
        this.db = db;
        this.guideStorage = Path.of(storagePath).toAbsolutePath().normalize().resolve("mail-guides").normalize();
    }

    public Map<String,Object> settings() {
        var setting = db.queryForMap("SELECT Cc_Emails,Bcc_Emails,Updated_At,Updated_By FROM activation_email_settings WHERE Id_Setting=1", Map.of());
        var systems = db.queryForList("SELECT s.Id_System,s.Name,s.Code,g.Original_File_Name,g.File_Size,g.Sha256,g.Is_Enabled,g.Modified_At "
                + "FROM systems s LEFT JOIN system_email_guides g ON g.Id_System=s.Id_System "
                + "WHERE s.System_Type='ANDROID' AND s.Is_Active=TRUE ORDER BY s.Name", Map.of());
        return Map.of("cc", split(setting.get("Cc_Emails")), "bcc", split(setting.get("Bcc_Emails")),
                "updatedAt", setting.get("Updated_At"), "updatedBy", Objects.toString(setting.get("Updated_By"), ""),
                "systems", systems);
    }

    public Map<String,Object> updateRecipients(Object ccValue, Object bccValue, String actor) {
        var cc = normalize(ccValue);
        var bcc = normalize(bccValue);
        bcc.removeAll(cc);
        db.update("UPDATE activation_email_settings SET Cc_Emails=:cc,Bcc_Emails=:bcc,Updated_By=:actor WHERE Id_Setting=1",
                Map.of("cc", String.join(",", cc), "bcc", String.join(",", bcc), "actor", actor));
        return Map.of("cc", List.copyOf(cc), "bcc", List.copyOf(bcc));
    }

    public RecipientCopies recoveryCopies(Collection<String> primaryRecipients) {
        var setting = db.queryForMap("SELECT Cc_Emails,Bcc_Emails FROM activation_email_settings WHERE Id_Setting=1", Map.of());
        var cc = new LinkedHashSet<>(split(setting.get("Cc_Emails")));
        var bcc = new LinkedHashSet<>(split(setting.get("Bcc_Emails")));
        var primary = new HashSet<String>();
        for (String recipient : primaryRecipients) primary.add(Objects.toString(recipient, "").trim().toLowerCase(Locale.ROOT));
        cc.removeAll(primary);
        bcc.removeAll(primary);
        bcc.removeAll(cc);
        return new RecipientCopies(List.copyOf(cc), List.copyOf(bcc));
    }

    public Delivery delivery(String systemId, String primaryRecipient) {
        var setting = db.queryForMap("SELECT Cc_Emails,Bcc_Emails FROM activation_email_settings WHERE Id_Setting=1", Map.of());
        var cc = new LinkedHashSet<>(split(setting.get("Cc_Emails")));
        var bcc = new LinkedHashSet<>(split(setting.get("Bcc_Emails")));
        String primary = primaryRecipient == null ? "" : primaryRecipient.trim().toLowerCase(Locale.ROOT);
        cc.remove(primary);
        bcc.remove(primary);
        bcc.removeAll(cc);
        Guide guide = null;
        var rows = db.queryForList("SELECT Original_File_Name,Storage_File_Name FROM system_email_guides WHERE Id_System=:system AND Is_Enabled=TRUE", Map.of("system", systemId));
        if (!rows.isEmpty()) {
            var row = rows.getFirst();
            Path path = guideStorage.resolve(row.get("Storage_File_Name").toString()).normalize();
            if (path.startsWith(guideStorage) && Files.isRegularFile(path)) guide = new Guide(row.get("Original_File_Name").toString(), path);
        }
        return new Delivery(List.copyOf(cc), List.copyOf(bcc), guide);
    }

    Path storage() { return guideStorage; }
    NamedParameterJdbcTemplate db() { return db; }

    private static LinkedHashSet<String> normalize(Object value) {
        Collection<?> values = value instanceof Collection<?> collection ? collection
                : List.of(Objects.toString(value, "").split("[,;\\r\\n]+"));
        var result = new LinkedHashSet<String>();
        for (Object item : values) {
            String email = Objects.toString(item, "").trim().toLowerCase(Locale.ROOT);
            if (email.isEmpty()) continue;
            if (email.length() > 254 || email.contains("\r") || email.contains("\n")) throw new IllegalArgumentException("Existe un correo CC/CCO no válido.");
            try { var address = new InternetAddress(email, true); address.validate(); }
            catch (Exception ex) { throw new IllegalArgumentException("Existe un correo CC/CCO no válido."); }
            result.add(email);
            if (result.size() > 50) throw new IllegalArgumentException("No se permiten más de 50 destinatarios por tipo.");
        }
        return result;
    }

    private static List<String> split(Object value) {
        String text = Objects.toString(value, "");
        if (text.isBlank()) return List.of();
        return Arrays.stream(text.split(",")).map(String::trim).filter(item -> !item.isEmpty()).toList();
    }
}
