package com.etic.licensecontrol.applications;

import com.etic.licensecontrol.common.CrudService;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/portal")
public class PortalController {
    private static final String ACCESS="ua.Is_Active=TRUE AND ua.Status='ACTIVE' AND ua.Valid_From<=CURRENT_DATE AND (ua.Valid_Until IS NULL OR ua.Valid_Until>=CURRENT_DATE)";
    private static final String VERSION_FIELDS="v.Id_Version id,v.Id_Application applicationId,a.Name applicationName,v.Version_Name versionName,v.Sha256 sha256,v.File_Size fileSize,v.Release_Notes releaseNotes,v.Minimum_Android minimumAndroid,v.Mandatory mandatory,v.Published published,v.Created_At createdAt";
    private final CrudService crud;
    private final Path storage;

    PortalController(CrudService crud,@Value("${license-control.storage.path}")String storage){this.crud=crud;this.storage=Path.of(storage).toAbsolutePath().normalize();}

    @GetMapping("/apps")
    List<Map<String,Object>> apps(Authentication auth){
        var rows=crud.db().queryForList("SELECT a.Id_Application id,a.Code code,a.Name name FROM licensed_applications a JOIN user_application_access ua ON ua.Id_Application=a.Id_Application WHERE ua.Id_Usuario=:user AND "+ACCESS+" AND a.Is_Active=TRUE AND a.Status='ACTIVE' ORDER BY a.Name,a.Id_Application",Map.of("user",auth.getName()));
        rows.forEach(this::latestVersion);
        return rows;
    }

    @GetMapping("/apps/{applicationId}")
    Map<String,Object> app(@PathVariable String applicationId,Authentication auth){
        var application=requireApplication(applicationId,auth.getName());
        latestVersion(application);
        return application;
    }

    @GetMapping("/apps/{applicationId}/versions")
    List<Map<String,Object>> versions(@PathVariable String applicationId,Authentication auth){
        requireApplication(applicationId,auth.getName());
        return publishedVersions(applicationId,false);
    }

    @GetMapping("/downloads/{versionId}")
    ResponseEntity<FileSystemResource> download(@PathVariable String versionId,Authentication auth)throws IOException{
        var rows=crud.db().queryForList("SELECT Id_Application,Storage_File_Name,Original_File_Name,Is_Active,Published FROM application_versions WHERE Id_Version=:version",Map.of("version",versionId));
        if(rows.isEmpty())throw missing();
        var version=rows.getFirst();
        requireApplication(version.get("Id_Application").toString(),auth.getName());
        if(!enabled(version.get("Is_Active"))||!enabled(version.get("Published")))throw missing();
        Path path;
        try{path=storage.resolve(version.get("Storage_File_Name").toString()).normalize();}
        catch(InvalidPathException ex){throw missingFile();}
        if(!path.startsWith(storage)||!Files.isRegularFile(path))throw missingFile();
        try{path=path.toRealPath();if(!path.startsWith(storage.toRealPath()))throw missingFile();}
        catch(NoSuchFileException ex){throw missingFile();}
        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION,ContentDisposition.attachment().filename(version.get("Original_File_Name").toString(),java.nio.charset.StandardCharsets.UTF_8).build().toString())
            .contentType(MediaType.parseMediaType("application/vnd.android.package-archive"))
            .body(new FileSystemResource(path));
    }

    private Map<String,Object> requireApplication(String applicationId,String user){
        var rows=crud.db().queryForList("SELECT Id_Application id,Code code,Name name FROM licensed_applications WHERE Id_Application=:app AND Is_Active=TRUE AND Status='ACTIVE'",Map.of("app",applicationId));
        if(rows.isEmpty())throw missing();
        Integer allowed=crud.db().queryForObject("SELECT COUNT(*) FROM user_application_access ua WHERE ua.Id_Usuario=:user AND ua.Id_Application=:app AND "+ACCESS,Map.of("app",applicationId,"user",user),Integer.class);
        if(allowed==null||allowed==0)throw new ResponseStatusException(HttpStatus.FORBIDDEN,"El usuario no tiene acceso a esta aplicación.");
        return rows.getFirst();
    }

    private void latestVersion(Map<String,Object> application){
        var versions=publishedVersions(application.get("id").toString(),true);
        application.put("latestVersion",versions.isEmpty()?null:versions.getFirst());
    }

    private List<Map<String,Object>> publishedVersions(String applicationId,boolean latest){
        var rows=crud.db().queryForList("SELECT "+VERSION_FIELDS+" FROM application_versions v JOIN licensed_applications a ON a.Id_Application=v.Id_Application WHERE v.Id_Application=:app AND v.Is_Active=TRUE AND v.Published=TRUE ORDER BY v.Created_At DESC,v.Id_Version DESC"+(latest?" LIMIT 1":""),Map.of("app",applicationId));
        rows.forEach(row->{CrudService.formatDates(row);row.put("mandatory",enabled(row.get("mandatory")));row.put("published",enabled(row.get("published")));});
        return rows;
    }

    private static boolean enabled(Object value){return Boolean.TRUE.equals(value)||value instanceof Number n&&n.intValue()!=0;}
    private static ResponseStatusException missing(){return new ResponseStatusException(HttpStatus.NOT_FOUND,"La aplicación o versión solicitada no existe.");}
    private static ResponseStatusException missingFile(){return new ResponseStatusException(HttpStatus.NOT_FOUND,"El archivo de esta versión no está disponible.");}
}
