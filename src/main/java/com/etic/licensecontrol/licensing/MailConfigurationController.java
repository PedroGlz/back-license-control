package com.etic.licensecontrol.licensing;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/admin/mail-settings")
public class MailConfigurationController {
    private static final long MAX_PDF_SIZE = 10L * 1024L * 1024L;
    private final MailConfigurationService service;

    public MailConfigurationController(MailConfigurationService service) { this.service = service; }

    @GetMapping Map<String,Object> settings() { return service.settings(); }

    @PutMapping("/recipients")
    Map<String,Object> recipients(@RequestBody Map<String,Object> body, Authentication auth) {
        return service.updateRecipients(body.get("cc"), body.get("bcc"), auth.getName());
    }

    @PostMapping(value="/systems/{systemId}/guide", consumes=MediaType.MULTIPART_FORM_DATA_VALUE)
    Map<String,Object> upload(@PathVariable String systemId, @RequestPart("file") MultipartFile file,
            Authentication auth) throws Exception {
        requireAndroidSystem(systemId);
        validate(file);
        Path storage = service.storage();
        Files.createDirectories(storage);
        if (!Files.isWritable(storage)) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"No fue posible escribir la guía en el almacenamiento del servidor.");
        String original = safeName(file.getOriginalFilename());
        String stored = UUID.randomUUID() + ".pdf";
        Path destination = storage.resolve(stored).normalize();
        if (!destination.startsWith(storage)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Nombre de archivo no válido.");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = new DigestInputStream(file.getInputStream(), digest)) { Files.copy(input, destination); }
        String sha = HexFormat.of().formatHex(digest.digest());
        var old = service.db().queryForList("SELECT Storage_File_Name FROM system_email_guides WHERE Id_System=:system",Map.of("system",systemId));
        try {
            service.db().update("INSERT INTO system_email_guides(Id_System,Original_File_Name,Storage_File_Name,File_Size,Sha256,Is_Enabled,Created_By) "
                    + "VALUES(:system,:original,:stored,:size,:sha,TRUE,:actor) ON DUPLICATE KEY UPDATE Original_File_Name=VALUES(Original_File_Name),Storage_File_Name=VALUES(Storage_File_Name),File_Size=VALUES(File_Size),Sha256=VALUES(Sha256),Is_Enabled=TRUE,Modified_At=UTC_TIMESTAMP(6),Modified_By=VALUES(Created_By)",
                    Map.of("system",systemId,"original",original,"stored",stored,"size",file.getSize(),"sha",sha,"actor",auth.getName()));
        } catch (Exception ex) { Files.deleteIfExists(destination); throw ex; }
        if (!old.isEmpty()) deleteStored(Objects.toString(old.getFirst().get("Storage_File_Name"),""));
        return Map.of("fileName",original,"fileSize",file.getSize(),"sha256",sha,"enabled",true);
    }

    @PutMapping("/systems/{systemId}/guide/enabled")
    void enabled(@PathVariable String systemId, @RequestBody Map<String,Object> body, Authentication auth) {
        requireAndroidSystem(systemId);
        boolean enabled = Boolean.TRUE.equals(body.get("enabled"));
        int changed = service.db().update("UPDATE system_email_guides SET Is_Enabled=:enabled,Modified_At=UTC_TIMESTAMP(6),Modified_By=:actor WHERE Id_System=:system",
                Map.of("enabled",enabled,"actor",auth.getName(),"system",systemId));
        if (changed == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"No hay una guía configurada para este sistema.");
    }

    @GetMapping("/systems/{systemId}/guide")
    ResponseEntity<FileSystemResource> download(@PathVariable String systemId) {
        requireAndroidSystem(systemId);
        var rows = service.db().queryForList("SELECT Original_File_Name,Storage_File_Name FROM system_email_guides WHERE Id_System=:system",Map.of("system",systemId));
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"No hay una guía configurada para este sistema.");
        var row = rows.getFirst(); Path path = service.storage().resolve(row.get("Storage_File_Name").toString()).normalize();
        if (!path.startsWith(service.storage()) || !Files.isRegularFile(path)) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"La guía no está disponible en el almacenamiento.");
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION,ContentDisposition.attachment().filename(row.get("Original_File_Name").toString(),java.nio.charset.StandardCharsets.UTF_8).build().toString())
                .body(new FileSystemResource(path));
    }

    private void requireAndroidSystem(String systemId) {
        Integer count = service.db().queryForObject("SELECT COUNT(*) FROM systems WHERE Id_System=:system AND System_Type='ANDROID' AND Is_Active=TRUE",Map.of("system",systemId),Integer.class);
        if (count == null || count == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Sistema Android no encontrado.");
    }
    private static void validate(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Selecciona un archivo PDF.");
        if (file.getSize() > MAX_PDF_SIZE) throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,"El PDF supera el máximo de 10 MB.");
        String name = safeName(file.getOriginalFilename());
        if (!name.toLowerCase(Locale.ROOT).endsWith(".pdf")) throw new ResponseStatusException(HttpStatus.UNSUPPORTED_MEDIA_TYPE,"El archivo debe ser PDF.");
        try (InputStream input = file.getInputStream()) {
            byte[] header = input.readNBytes(5);
            if (!Arrays.equals(header,new byte[]{'%', 'P', 'D', 'F', '-'})) throw new ResponseStatusException(HttpStatus.UNSUPPORTED_MEDIA_TYPE,"El archivo no contiene un PDF válido.");
        }
    }
    private static String safeName(String value) {
        String name = value == null ? "" : Path.of(value.replace('\\','/')).getFileName().toString();
        if (name.isBlank() || name.length() > 255 || !name.matches("[\\p{L}\\p{N}._() \\-]+")) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Nombre de archivo no válido.");
        return name;
    }
    private void deleteStored(String file) {
        try { Path path=service.storage().resolve(file).normalize(); if(path.startsWith(service.storage()))Files.deleteIfExists(path); }
        catch(IOException ignored) { org.slf4j.LoggerFactory.getLogger(getClass()).warn("No fue posible retirar la guía reemplazada del almacenamiento."); }
    }
}
