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

@RestController @RequestMapping("/api/admin/systems/{systemId}/versions")
public class VersionController {
    private final CrudService crud;
    private final Path storage;
    private final long maxApkSize;
    private static final CrudService.Definition D=new CrudService.Definition("application_versions","Id_Version",List.of("Id_System","Version_Name","Original_File_Name","Storage_File_Name","Sha256","File_Size","Minimum_Android","Release_Notes","Mandatory","Published","Created_At","Created_By","Modified_At","Modified_By"),List.of("Id_System","Version_Name","Original_File_Name","Storage_File_Name","Sha256","File_Size","Created_By"));
    VersionController(CrudService crud,@Value("${license-control.storage.path}")String path,@Value("${spring.servlet.multipart.max-file-size}")String maxSize){this.crud=crud;this.storage=Path.of(path).toAbsolutePath().normalize();this.maxApkSize=org.springframework.util.unit.DataSize.parse(maxSize).toBytes();}
    @GetMapping List<Map<String,Object>> list(@PathVariable String systemId,@RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="25")int size,@RequestParam(defaultValue="")String search,@RequestParam(defaultValue="Created_At")String sort,@RequestParam(defaultValue="desc")String direction){var filters=Map.of("Id_System",systemId);var rows=crud.filtered(D,search,page,size,filters,sort,direction);rows.forEach(VersionController::publicVersion);return rows;}
    @PostMapping(consumes=MediaType.MULTIPART_FORM_DATA_VALUE)
    Map<String,Object> upload(@PathVariable String systemId,@RequestPart(value="file",required=false)MultipartFile file,@RequestParam(required=false)String versionName,@RequestParam(required=false)String minimumAndroid,@RequestParam(required=false)String releaseNotes,@RequestParam(defaultValue="false")boolean mandatory,@RequestParam(defaultValue="false")boolean published,Authentication auth)throws Exception {
        if(file==null)throw failure(HttpStatus.BAD_REQUEST,"Debes seleccionar un archivo APK.",null);
        if(file.isEmpty())throw failure(HttpStatus.BAD_REQUEST,"El archivo APK está vacío.",null);
        if(file.getOriginalFilename()==null||!file.getOriginalFilename().toLowerCase(Locale.ROOT).endsWith(".apk")||(file.getContentType()!=null&&!Set.of("application/vnd.android.package-archive","application/octet-stream","application/zip","application/x-zip-compressed").contains(file.getContentType().toLowerCase(Locale.ROOT))))throw failure(HttpStatus.UNSUPPORTED_MEDIA_TYPE,"El archivo seleccionado no es un APK válido.",null);
        if(maxApkSize>=0&&file.getSize()>maxApkSize)throw failure(HttpStatus.PAYLOAD_TOO_LARGE,"El APK supera el tamaño máximo permitido.",null);
        if(crud.db().queryForObject("SELECT COUNT(*) FROM systems s JOIN system_licensing sl ON sl.Id_System=s.Id_System WHERE s.Id_System=:id AND s.Is_Active=TRUE AND s.Status='ACTIVE' AND sl.Is_Active=TRUE",Map.of("id",systemId),Integer.class)==0)throw failure(HttpStatus.NOT_FOUND,"El sistema seleccionado no existe o no tiene licenciamiento activo.",null);
        if(versionName==null||versionName.isBlank())throw failure(HttpStatus.BAD_REQUEST,"Debes indicar la versión.",null);
        if(versionName.length()>80)throw new IllegalArgumentException("La versión no debe exceder 80 caracteres.");
        try{
            Files.createDirectories(storage);
            if(!Files.isDirectory(storage))throw failure(HttpStatus.SERVICE_UNAVAILABLE,"No fue posible acceder al almacenamiento de aplicaciones.",null);
            if(!Files.isWritable(storage))throw failure(HttpStatus.SERVICE_UNAVAILABLE,"No fue posible escribir el APK en el almacenamiento del servidor.",null);
            if(Files.getFileStore(storage).getUsableSpace()<file.getSize())throw failure(HttpStatus.INSUFFICIENT_STORAGE,"No hay espacio suficiente para almacenar el APK.",null);
        }catch(java.nio.file.AccessDeniedException|SecurityException e){throw failure(HttpStatus.SERVICE_UNAVAILABLE,"No fue posible escribir el APK en el almacenamiento del servidor.",e);}
        catch(java.io.IOException e){throw storageFailure(e,"No fue posible acceder al almacenamiento de aplicaciones.");}
        String name=UUID.randomUUID().toString()+".apk";Path destination=storage.resolve(name);
        try{
            MessageDigest digest;
            try{digest=MessageDigest.getInstance("SHA-256");}catch(NoSuchAlgorithmException e){throw failure(HttpStatus.INTERNAL_SERVER_ERROR,"No fue posible procesar el APK.",e);}
            try(var input=new DigestInputStream(file.getInputStream(),digest)){Files.copy(input,destination);}
            catch(java.nio.file.AccessDeniedException|SecurityException e){throw failure(HttpStatus.SERVICE_UNAVAILABLE,"No fue posible escribir el APK en el almacenamiento del servidor.",e);}
            catch(java.io.IOException e){throw storageFailure(e,"No fue posible guardar el APK en el servidor.");}
            try(var zip=new ZipFile(destination.toFile())){if(zip.getEntry("AndroidManifest.xml")==null)throw failure(HttpStatus.UNSUPPORTED_MEDIA_TYPE,"El archivo seleccionado no es un APK válido.",null);}
            catch(java.util.zip.ZipException e){throw failure(HttpStatus.UNSUPPORTED_MEDIA_TYPE,"El archivo seleccionado no es un APK válido.",e);}
            catch(java.io.IOException e){throw storageFailure(e,"No fue posible leer el APK del almacenamiento del servidor.");}
            Map<String,Object> body=new HashMap<>();body.put("Id_System",systemId);body.put("Version_Name",versionName);body.put("Original_File_Name",Path.of(file.getOriginalFilename().replace('\\','/')).getFileName().toString());body.put("Storage_File_Name",name);body.put("Sha256",HexFormat.of().formatHex(digest.digest()));body.put("File_Size",Files.size(destination));body.put("Minimum_Android",minimumAndroid);body.put("Release_Notes",releaseNotes);body.put("Mandatory",mandatory);body.put("Published",published);body.put("Created_At",java.time.LocalDateTime.now().toString());body.put("Created_By",auth.getName());return publicVersion(crud.create(D,body));
        }catch(Exception e){try{Files.deleteIfExists(destination);}catch(java.io.IOException|SecurityException cleanup){e.addSuppressed(cleanup);}throw e;}
    }
    private static Map<String,Object> publicVersion(Map<String,Object> row){var fields=new HashSet<>(D.writable());fields.add(D.id());fields.add("Is_Active");row.keySet().retainAll(fields);return row;}
    private static org.springframework.web.server.ResponseStatusException failure(HttpStatus status,String message,Throwable cause){return new org.springframework.web.server.ResponseStatusException(status,message,cause);}
    private static org.springframework.web.server.ResponseStatusException storageFailure(java.io.IOException cause,String message){
        String reason=Objects.toString(cause.getMessage(),"").toLowerCase(Locale.ROOT);
        return reason.contains("no space")||reason.contains("not enough space")||reason.contains("disk full")?failure(HttpStatus.INSUFFICIENT_STORAGE,"No hay espacio suficiente para almacenar el APK.",cause):failure(HttpStatus.SERVICE_UNAVAILABLE,message,cause);
    }
    @PutMapping("/{id}") Map<String,Object> update(@PathVariable String systemId,@PathVariable String id,@RequestBody Map<String,Object> body,Authentication auth){var row=crud.get(D,id);if(!systemId.equals(row.get("Id_System")))throw new IllegalArgumentException("Versión inválida para la aplicación");Map<String,Object> allowed=new HashMap<>();for(String k:List.of("Version_Name","Minimum_Android","Release_Notes","Mandatory","Published"))if(body.containsKey(k))allowed.put(k,body.get(k));allowed.put("Modified_At",java.time.LocalDateTime.now().toString());allowed.put("Modified_By",auth.getName());return publicVersion(crud.update(D,id,allowed));}
    @DeleteMapping("/{id}") void deactivate(@PathVariable String systemId,@PathVariable String id){if(!systemId.equals(crud.get(D,id).get("Id_System")))throw new IllegalArgumentException("Versión inválida");crud.deactivate(D,id);}
    @GetMapping("/{id}/file") ResponseEntity<FileSystemResource> download(@PathVariable String systemId,@PathVariable String id){var row=crud.get(D,id);if(!systemId.equals(row.get("Id_System")))throw new IllegalArgumentException("Versión inválida");Path path=storage.resolve(row.get("Storage_File_Name").toString()).normalize();if(!path.startsWith(storage)||!Files.isRegularFile(path))throw new org.springframework.web.server.ResponseStatusException(HttpStatus.NOT_FOUND,"Archivo no disponible en el almacenamiento configurado");return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION,ContentDisposition.attachment().filename(row.get("Original_File_Name").toString(),java.nio.charset.StandardCharsets.UTF_8).build().toString()).contentType(MediaType.APPLICATION_OCTET_STREAM).body(new FileSystemResource(path));}
}
