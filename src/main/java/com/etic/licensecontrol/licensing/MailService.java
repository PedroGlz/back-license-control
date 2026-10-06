package com.etic.licensecontrol.licensing;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {
    private final ObjectProvider<JavaMailSender> sender;
    private final String host,from;
    public MailService(ObjectProvider<JavaMailSender> sender,@Value("${spring.mail.host:}") String host,@Value("${license-control.mail.from:}") String from) {
        this.sender=sender;this.host=host;this.from=from;
    }
    public boolean sendActivationCodes(String email,String customer,String system,List<String> codes,Instant expires,String term,int seats) {
        try {
            var mail=sender.getIfAvailable();
            if(mail==null||host.isBlank()||from.isBlank())return false;
            var message=new SimpleMailMessage();message.setFrom(from);message.setTo(email);
            message.setSubject("Códigos de activación - "+system.replaceAll("[\\r\\n]"," "));
            String validity=switch(term){case "MONTHLY"->"Mensual";case "ANNUAL"->"Anual";case "PERPETUAL"->"Permanente";default->throw new IllegalArgumentException();};
            String date=DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm 'UTC'").withZone(ZoneOffset.UTC).format(expires);
            message.setText("Hola "+customer+",\n\nSe generaron los siguientes códigos de activación para "+system+":\n\n"+String.join("\n",codes)
                +"\n\nCada código permite activar un dispositivo y solo puede utilizarse una vez.\n\nVigencia de los códigos:\n"+date
                +"\n\nLicencia:\n"+validity+"\n\nDispositivos contratados:\n"+seats
                +"\n\nImportante:\nLa instalación del APK no activa automáticamente una licencia. El código debe introducirse durante la activación inicial de la aplicación.\n\nSaludos,\nETIC License Control");
            mail.send(message);return true;
        } catch(Exception ex) {
            // MailException puede incluir el mensaje y sus códigos: nunca registrar su texto ni causa.
            return false;
        }
    }
}
