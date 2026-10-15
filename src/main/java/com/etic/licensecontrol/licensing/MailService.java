package com.etic.licensecontrol.licensing;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class MailService {
    private static final Logger log = LoggerFactory.getLogger(MailService.class);
    private static final String SUITE_URL = "https://suite.etic-system.online/";
    private static final ZoneId MEXICO_CITY = ZoneId.of("America/Mexico_City");
    private static final Locale SPANISH_MEXICO = new Locale("es", "MX");
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter
            .ofPattern("d 'de' MMMM 'de' uuuu, h:mm", SPANISH_MEXICO);
    private static final ClassPathResource TEMPLATE = new ClassPathResource("mail/activation-codes.html");
    private static final ClassPathResource LOGO = new ClassPathResource("mail/etic-logo.png");
    private static final ClassPathResource RESET_ADMIN_TEMPLATE = new ClassPathResource("mail/password-reset-admin.html");
    private static final ClassPathResource TEMPORARY_PASSWORD_TEMPLATE = new ClassPathResource("mail/temporary-password.html");

    private final ObjectProvider<JavaMailSender> sender;
    private final MailConfigurationService configuration;
    private final String host;
    private final String from;

    public MailService(ObjectProvider<JavaMailSender> sender, MailConfigurationService configuration,
            @Value("${spring.mail.host:}") String host,
            @Value("${license-control.mail.from:}") String from) {
        this.sender = sender;
        this.configuration = configuration;
        this.host = host;
        this.from = from;
    }

    public boolean sendActivationCodes(String email, String owner, String systemId, String system, List<String> codes,
            Instant expires, String term, int seats) {
        try {
            var mail = sender.getIfAvailable();
            if (mail == null || host.isBlank() || from.isBlank()) {
                log.error("Configuración SMTP incompleta; no se enviaron los códigos de activación");
                return false;
            }
            var message = mail.createMimeMessage();
            var helper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
            helper.setFrom(from);
            helper.setTo(email);
            var delivery = configuration.delivery(systemId, email);
            if (!delivery.cc().isEmpty()) helper.setCc(delivery.cc().toArray(String[]::new));
            if (!delivery.bcc().isEmpty()) helper.setBcc(delivery.bcc().toArray(String[]::new));
            helper.setSubject("Tu código de activación está listo - " + plainText(system));
            helper.setText(render(owner, system, codes, expires, term, seats), true);
            helper.addInline("eticLogo", LOGO, "image/png");
            if (delivery.guide() != null) helper.addAttachment(delivery.guide().originalName(),
                    new FileSystemResource(delivery.guide().path()), "application/pdf");
            mail.send(message);
            return true;
        } catch (Exception ex) {
            log.error("Falló el envío SMTP de códigos de activación. Tipo={}",
                    ex.getClass().getName(), ex);
            return false;
        }
    }

    public boolean notifyPasswordResetAdmins(List<String> recipients, String username, String email,
            String system, Instant requestedAt) {
        if (recipients.isEmpty()) return false;
        try {
            String body = RESET_ADMIN_TEMPLATE.getContentAsString(StandardCharsets.UTF_8)
                    .replace("{{USERNAME}}", html(username)).replace("{{EMAIL}}", html(email))
                    .replace("{{SYSTEM}}", html(system)).replace("{{DATE}}", html(localDate(requestedAt)));
            return sendHtml(recipients.toArray(String[]::new), "Solicitud de restablecimiento de contraseña", body);
        } catch (Exception ex) {
            log.error("Falló la notificación de recuperación a Super Administradores. Tipo={}", ex.getClass().getName(), ex);
            return false;
        }
    }

    public boolean sendTemporaryPassword(String recipient, String name, String temporaryPassword, Instant expiresAt) {
        try {
            String greeting = name == null || name.isBlank() ? "Hola" : "Hola " + name.trim();
            String body = TEMPORARY_PASSWORD_TEMPLATE.getContentAsString(StandardCharsets.UTF_8)
                    .replace("{{GREETING}}", html(greeting)).replace("{{PASSWORD}}", html(temporaryPassword))
                    .replace("{{EXPIRES}}", html(localDate(expiresAt)));
            return sendHtml(new String[]{recipient}, "Tu contraseña temporal de acceso", body);
        } catch (Exception ex) {
            log.error("Falló el envío de contraseña temporal. Tipo={}", ex.getClass().getName(), ex);
            return false;
        }
    }

    private boolean sendHtml(String[] recipients, String subject, String body) throws Exception {
        var mail = sender.getIfAvailable();
        if (mail == null || host.isBlank() || from.isBlank()) return false;
        var message = mail.createMimeMessage();
        var helper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
        helper.setFrom(from); helper.setTo(recipients); helper.setSubject(subject); helper.setText(body, true);
        helper.addInline("eticLogo", LOGO, "image/png");
        mail.send(message); return true;
    }

    private static String localDate(Instant value) {
        var local = value.atZone(MEXICO_CITY);
        return DATE_FORMAT.format(local) + (local.getHour() < 12 ? " a. m." : " p. m.");
    }

    private static String render(String owner, String system, List<String> codes,
            Instant expires, String term, int seats) throws java.io.IOException {
        String codeBlocks = codes.stream()
                .map(code -> "<div style=\"margin:8px 0;padding:15px 12px;background:#eaf3ff;"
                        + "border:1px solid #9dc5ef;border-radius:8px;color:#082f5b;font-family:Consolas,"
                        + "'Courier New',monospace;font-size:18px;font-weight:bold;letter-spacing:1px;"
                        + "word-break:break-all;\">" + html(code) + "</div>")
                .collect(Collectors.joining());
        var localExpiration = expires.atZone(MEXICO_CITY);
        String dayPeriod = localExpiration.getHour() < 12 ? "a. m." : "p. m.";
        String expiration = DATE_FORMAT.format(localExpiration) + " " + dayPeriod;
        String validity = switch (term) {
            case "MONTHLY" -> "Mensual";
            case "ANNUAL" -> "Anual";
            case "PERPETUAL" -> "Permanente";
            default -> throw new IllegalArgumentException("Vigencia no válida");
        };
        String greeting = owner == null || owner.isBlank() ? "Hola" : "Hola " + owner.trim();
        return TEMPLATE.getContentAsString(StandardCharsets.UTF_8)
                .replace("{{GREETING}}", html(greeting))
                .replace("{{SYSTEM}}", html(system))
                .replace("{{CODES}}", codeBlocks)
                .replace("{{EXPIRES}}", html(expiration))
                .replace("{{TERM}}", html(validity))
                .replace("{{SEATS}}", Integer.toString(seats))
                .replace("{{SUITE_URL}}", SUITE_URL);
    }

    private static String plainText(String value) {
        return value == null ? "Aplicación" : value.replaceAll("[\\r\\n]", " ").trim();
    }

    private static String html(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }
}
