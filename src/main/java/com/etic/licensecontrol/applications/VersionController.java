package com.etic.licensecontrol.applications;
import com.etic.licensecontrol.common.CrudService;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.zip.ZipFile;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController @RequestMapping("/api/admin/applications/{applicationId}/versions")
public class VersionController {
    private final CrudService crud;
    private final Path storage;
    private static final CrudService.Definition D=new CrudService.Definition("application_versions","Id_Version",List.of("Id_Application","Version_Name","Version_Code","Original_File_Name","Storage_File_Name","Sha256","File_Size","Minimum_Android","Release_Notes","Mandatory","Published","Created_At","Created_By","Modified_At","Modified_By"),List.of("Version_Name","Original_File_Name","Storage_File_Name","Sha256","File_Size","Created_By"));
    VersionController(CrudService crud,@Value("${license-control.storage.path}")String path){this.crud=crud;this.storage=Path.of(path).toAbsolutePath().normalize();}
    @GetMapping List<Map<String,Object>> list(@PathVariable String applicationId,@RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="25")int size,@RequestParam(defaultValue="")String search,@RequestParam(defaultValue="Created_At")String sort,@RequestParam(defaultValue="desc")String direction){var filters=Map.of("Id_Application",applicationId);return crud.filtered(D,search,page,size,filters,sort,direction);}
    @PostMapping(consumes=MediaType.MULTIPART_FORM_DATA_VALUE)
    Map<String,Object> upload(@PathVariable String applicationId,@RequestPart("file")MultipartFile file,@RequestParam String versionName,@RequestParam(required=false)Long versionCode,@RequestParam(required=false)String minimumAndroid,@RequestParam(required=false)String releaseNotes,@RequestParam(defaultValue="false")boolean mandatory,@RequestParam(defaultValue="false")boolean published,Authentication auth)throws Exception {
        if(file.isEmpty()||file.getOriginalFilename()==null||!file.getOriginalFilename().toLowerCase(Locale.ROOT).endsWith(".apk"))throw new IllegalArgumentException("Seleccione un archivo APK");
        if(crud.db().queryForObject("SELECT COUNT(*) FROM licensed_applications WHERE Id_Application=:id AND Is_Active=TRUE",Map.of("id",applicationId),Integer.class)==0)throw new IllegalArgumentException("Aplicación inválida");
        if(versionName.isBlank()||versionName.length()>80)throw new IllegalArgumentException("Nombre de versión obligatorio (máximo 80 caracteres)");
        if(versionCode!=null&&versionCode<0)throw new IllegalArgumentException("VersionCode inválido");
        Files.createDirectories(storage);String name=UUID.randomUUID().toString()+".apk";Path destination=storage.resolve(name);
        try{
            MessageDigest digest=MessageDigest.getInstance("SHA-256");try(var input=new DigestInputStream(file.getInputStream(),digest)){Files.copy(input,destination);}
            try(var zip=new ZipFile(destination.toFile())){if(zip.getEntry("AndroidManifest.xml")==null)throw new IllegalArgumentException("El archivo no contiene un AndroidManifest.xml");}
            Map<String,Object> body=new HashMap<>();body.put("Id_Application",applicationId);body.put("Version_Name",versionName);body.put("Version_Code",versionCode);body.put("Original_File_Name",Path.of(file.getOriginalFilename().replace('\\','/')).getFileName().toString());body.put("Storage_File_Name",name);body.put("Sha256",HexFormat.of().formatHex(digest.digest()));body.put("File_Size",Files.size(destination));body.put("Minimum_Android",minimumAndroid);body.put("Release_Notes",releaseNotes);body.put("Mandatory",mandatory);body.put("Published",published);body.put("Created_At",java.time.LocalDateTime.now().toString());body.put("Created_By",auth.getName());return crud.create(D,body);
        }catch(Exception e){Files.deleteIfExists(destination);throw e;}
    }
    @PutMapping("/{id}") Map<String,Object> update(@PathVariable String applicationId,@PathVariable String id,@RequestBody Map<String,Object> body,Authentication auth){var row=crud.get(D,id);if(!applicationId.equals(row.get("Id_Application")))throw new IllegalArgumentException("Versión inválida para la aplicación");Map<String,Object> allowed=new HashMap<>();for(String k:List.of("Version_Name","Minimum_Android","Release_Notes","Version_Code","Mandatory","Published"))if(body.containsKey(k))allowed.put(k,body.get(k));allowed.put("Modified_At",java.time.LocalDateTime.now().toString());allowed.put("Modified_By",auth.getName());return crud.update(D,id,allowed);}
    @DeleteMapping("/{id}") void deactivate(@PathVariable String applicationId,@PathVariable String id){if(!applicationId.equals(crud.get(D,id).get("Id_Application")))throw new IllegalArgumentException("Versión inválida");crud.deactivate(D,id);}
    @GetMapping("/{id}/file") ResponseEntity<FileSystemResource> download(@PathVariable String applicationId,@PathVariable String id){var row=crud.get(D,id);if(!applicationId.equals(row.get("Id_Application")))throw new IllegalArgumentException("Versión inválida");Path path=storage.resolve(row.get("Storage_File_Name").toString()).normalize();if(!path.startsWith(storage)||!Files.isRegularFile(path))throw new org.springframework.web.server.ResponseStatusException(HttpStatus.NOT_FOUND,"Archivo no disponible en el almacenamiento configurado");return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION,ContentDisposition.attachment().filename(row.get("Original_File_Name").toString(),java.nio.charset.StandardCharsets.UTF_8).build().toString()).contentType(MediaType.APPLICATION_OCTET_STREAM).body(new FileSystemResource(path));}
}
