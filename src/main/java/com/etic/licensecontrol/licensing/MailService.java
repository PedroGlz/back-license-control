package com.etic.licensecontrol.licensing;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {
    private static final Logger log = LoggerFactory.getLogger(MailService.class);
    private final ObjectProvider<JavaMailSender> sender;
    private final String host;
    private final String from;

    public MailService(ObjectProvider<JavaMailSender> sender,
            @Value("${spring.mail.host:}") String host,
            @Value("${license-control.mail.from:}") String from) {
        this.sender = sender;
        this.host = host;
        this.from = from;
    }

    public boolean sendActivationCodes(String email, String owner, String system, List<String> codes,
            Instant expires, String term, int seats) {
        try {
            var mail = sender.getIfAvailable();
            if (mail == null || host.isBlank() || from.isBlank()) {
                log.error("Configuración SMTP incompleta; no se enviaron los códigos de activación");
                return false;
            }
            var message = new SimpleMailMessage();
            message.setFrom(from);
            message.setTo(email);
            message.setSubject("Códigos de activación - " + system.replaceAll("[\\r\\n]", " "));
            String validity = switch (term) {
                case "MONTHLY" -> "Mensual";
                case "ANNUAL" -> "Anual";
                case "PERPETUAL" -> "Permanente";
                default -> throw new IllegalArgumentException("Vigencia no válida");
            };
            String date = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm 'UTC'")
                    .withZone(ZoneOffset.UTC).format(expires);
            message.setText("Hola " + owner + ",\n\n"
                    + "ETIC License Control generó los siguientes códigos de activación para " + system + ":\n\n"
                    + String.join("\n", codes)
                    + "\n\nCada código permite activar un dispositivo y solo puede utilizarse una vez."
                    + "\n\nVencimiento de los códigos:\n" + date
                    + "\n\nLicencia:\n" + validity
                    + "\n\nDispositivos contratados:\n" + seats
                    + "\n\nAbra la APK e introduzca uno de los códigos en la pantalla de activación."
                    + "\n\nSaludos,\nETIC License Control");
            mail.send(message);
            return true;
        } catch (Exception ex) {
            log.error("Falló el envío SMTP de códigos de activación. Tipo={}",
                    ex.getClass().getName(), ex);
            return false;
        }
    }
}
