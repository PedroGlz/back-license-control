package com.etic.licensecontrol.common;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.*;
import org.springframework.dao.*;
import org.springframework.http.*;
import org.springframework.web.bind.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.multipart.*;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

@RestControllerAdvice
public class ApiExceptionHandler {
    private static final org.slf4j.Logger log=org.slf4j.LoggerFactory.getLogger(ApiExceptionHandler.class);
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String,Object>> handle(Exception ex,HttpServletRequest req){
        HttpStatus status=HttpStatus.INTERNAL_SERVER_ERROR;
        String message=isApkUpload(req)?"No fue posible cargar el APK. Consulta al administrador.":"No fue posible completar la operación. Consulta al administrador.";
        java.sql.SQLException sql=findSqlException(ex);
        int sqlCode=sql==null?0:sql.getErrorCode();
        if(sqlCode==1364){message="La configuración requerida para completar la operación está incompleta en el servidor.";}
        else if(sqlCode==1054){message="La configuración de datos del servidor no está actualizada.";}
        else if(sqlCode==1062){status=HttpStatus.CONFLICT;message=integrityMessage(sql);}
        else if(sqlCode==1451||sqlCode==1452){status=sqlCode==1451?HttpStatus.CONFLICT:HttpStatus.BAD_REQUEST;message="Existe una relación inválida o el registro está siendo utilizado.";}
        else if(diskFull(ex)){status=HttpStatus.INSUFFICIENT_STORAGE;message="No hay espacio suficiente para almacenar el archivo.";}
        else if(storageDenied(ex)){status=HttpStatus.SERVICE_UNAVAILABLE;message="No fue posible escribir el archivo en el almacenamiento del servidor.";}
        else if(ex instanceof ResponseStatusException r){status=HttpStatus.valueOf(r.getStatusCode().value());message=status==HttpStatus.SERVICE_UNAVAILABLE&&storageFailure(ex)?"No fue posible escribir el archivo en el almacenamiento del servidor.":safeMessage(r.getReason(),message);}
        else if(ex instanceof org.springframework.security.core.AuthenticationException){status=HttpStatus.UNAUTHORIZED;message="Sesión inválida o expirada.";}
        else if(ex instanceof org.springframework.security.access.AccessDeniedException){status=HttpStatus.FORBIDDEN;message="El usuario no tiene permiso para realizar esta operación.";}
        else if(ex instanceof MaxUploadSizeExceededException){status=HttpStatus.PAYLOAD_TOO_LARGE;message="El APK supera el tamaño máximo permitido.";}
        else if(ex instanceof MissingServletRequestPartException p){status=HttpStatus.BAD_REQUEST;message="file".equals(p.getRequestPartName())?"Debes seleccionar un archivo APK.":"Falta un archivo obligatorio en la solicitud.";}
        else if(ex instanceof MissingServletRequestParameterException p){status=HttpStatus.BAD_REQUEST;message="versionName".equals(p.getParameterName())?"Debes indicar la versión.":"Falta un campo obligatorio en la solicitud.";}
        else if(ex instanceof org.springframework.web.HttpMediaTypeNotSupportedException){status=HttpStatus.UNSUPPORTED_MEDIA_TYPE;message="El tipo de contenido enviado no está permitido.";}
        else if(ex instanceof org.springframework.web.HttpRequestMethodNotSupportedException){status=HttpStatus.METHOD_NOT_ALLOWED;message="El método HTTP no está permitido para este recurso.";}
        else if(ex instanceof org.springframework.web.HttpMediaTypeNotAcceptableException){status=HttpStatus.NOT_ACCEPTABLE;message="El formato de respuesta solicitado no está disponible.";}
        else if(ex instanceof org.springframework.web.servlet.resource.NoResourceFoundException){status=HttpStatus.NOT_FOUND;message="El recurso solicitado no existe.";}
        else if(ex instanceof MultipartException){status=HttpStatus.BAD_REQUEST;message="No fue posible leer el archivo enviado. Revisa la solicitud multipart.";}
        else if(ex instanceof MethodArgumentNotValidException v){status=HttpStatus.BAD_REQUEST;message=validationMessage(v.getBindingResult());}
        else if(ex instanceof org.springframework.validation.BindException v){status=HttpStatus.BAD_REQUEST;message=validationMessage(v.getBindingResult());}
        else if(ex instanceof jakarta.validation.ConstraintViolationException||ex instanceof org.springframework.web.method.annotation.HandlerMethodValidationException){status=HttpStatus.BAD_REQUEST;message="Revisa los campos obligatorios y el formato de los datos enviados.";}
        else if(ex instanceof org.springframework.http.converter.HttpMessageNotReadableException||ex instanceof org.springframework.web.method.annotation.MethodArgumentTypeMismatchException){status=HttpStatus.BAD_REQUEST;message="El formato de los datos enviados no es válido.";}
        else if(ex instanceof DataIntegrityViolationException d){
            status=HttpStatus.CONFLICT;message=integrityMessage(d);
            Throwable cause=d.getMostSpecificCause();
            if(cause instanceof java.sql.SQLException integritySql){
                if(integritySql.getErrorCode()==1048||integritySql.getErrorCode()==1406){status=HttpStatus.BAD_REQUEST;message="Revisa los campos obligatorios y sus longitudes máximas.";}
            }
        }
        else if(databaseUnavailable(ex)){status=HttpStatus.SERVICE_UNAVAILABLE;message="La base de datos no está disponible. Intenta nuevamente más tarde.";}
        else if(ex instanceof org.springframework.web.client.ResourceAccessException){status=HttpStatus.SERVICE_UNAVAILABLE;message="El servicio requerido no está disponible. Intenta nuevamente más tarde.";}
        else if(ex instanceof java.time.format.DateTimeParseException||ex instanceof NumberFormatException){status=HttpStatus.BAD_REQUEST;message="Revisa el formato de los números, identificadores y fechas enviados.";}
        else if(ex instanceof EmptyResultDataAccessException){status=HttpStatus.NOT_FOUND;message="El registro solicitado no existe.";}
        else if(ex instanceof DataAccessResourceFailureException||ex instanceof TransientDataAccessResourceException||ex instanceof RecoverableDataAccessException){status=HttpStatus.SERVICE_UNAVAILABLE;message="La base de datos no está disponible. Intenta nuevamente más tarde.";}
        else if(storageFailure(ex)){status=HttpStatus.SERVICE_UNAVAILABLE;message="No fue posible escribir el archivo en el almacenamiento del servidor.";}
        else if(ex instanceof IllegalArgumentException){status=HttpStatus.BAD_REQUEST;message=safeMessage(ex.getMessage(),"Los datos enviados no son válidos.");if(message.matches("(?is).*(ya existe|ya está (asignad|registrad)).*"))status=HttpStatus.CONFLICT;}
        if(status.is5xxServerError()||sql!=null||ex instanceof DataIntegrityViolationException||ex.getCause()!=null)
            log.error("Error en {} {}",req.getMethod(),req.getRequestURI(),sanitized(ex,0));
        return ResponseEntity.status(status).body(body(status,message,req));
    }
    private static java.sql.SQLException findSqlException(Throwable error){
        java.sql.SQLException first=null;
        for(int depth=0;error!=null&&depth<16;depth++,error=error.getCause()){
            if(error instanceof java.sql.SQLException sql){
                for(int next=0;sql!=null&&next<16;next++,sql=sql.getNextException()){
                    if(first==null)first=sql;
                    if(Set.of(1364,1054,1062,1451,1452).contains(sql.getErrorCode()))return sql;
                }
            }
        }
        return first;
    }
    private static boolean storageFailure(Throwable error){
        for(int depth=0;error!=null&&depth<16;depth++,error=error.getCause())if(error instanceof java.io.IOException)return true;
        return false;
    }
    private static boolean storageDenied(Throwable error){
        for(int depth=0;error!=null&&depth<16;depth++,error=error.getCause())
            if(error instanceof java.nio.file.AccessDeniedException||error instanceof SecurityException)return true;
        return false;
    }
    private static boolean diskFull(Throwable error){
        for(int depth=0;error!=null&&depth<16;depth++,error=error.getCause()){
            if(error instanceof java.io.IOException){
                String reason=Objects.toString(error.getMessage(),"").toLowerCase(Locale.ROOT);
                if(reason.contains("no space left")||reason.contains("not enough space")||reason.contains("disk full")||reason.contains("insufficient disk space")||reason.contains("espacio insuficiente")||reason.contains("no hay espacio suficiente")||reason.contains("disco lleno"))return true;
            }
        }
        return false;
    }
    private static boolean databaseUnavailable(Throwable error){
        for(int depth=0;error!=null&&depth<16;depth++,error=error.getCause()){
            if(error instanceof DataAccessResourceFailureException||error instanceof org.springframework.jdbc.CannotGetJdbcConnectionException)return true;
            if(error instanceof java.sql.SQLException sql&&sql.getSQLState()!=null&&sql.getSQLState().startsWith("08"))return true;
        }
        return false;
    }
    private static boolean isApkUpload(HttpServletRequest req){return "POST".equals(req.getMethod())&&req.getRequestURI().matches(".*/applications/[^/]+/versions");}
    public static Map<String,Object> body(HttpStatus status,String message,HttpServletRequest req){
        var body=new LinkedHashMap<String,Object>();body.put("timestamp",Instant.now().toString());body.put("status",status.value());body.put("error",status.getReasonPhrase());body.put("message",message);body.put("path",req.getRequestURI());return body;
    }
    public static void write(HttpServletRequest req,HttpServletResponse res,HttpStatus status,String message)throws java.io.IOException{
        res.setStatus(status.value());res.setContentType("application/json;charset=UTF-8");
        res.getWriter().write(tools.jackson.databind.json.JsonMapper.builder().build().writeValueAsString(body(status,message,req)));
    }
    private static String validationMessage(org.springframework.validation.BindingResult result){
        return result.getFieldErrors().stream().findFirst().map(e->"El campo "+fieldLabel(e.getField())+" "+safeMessage(e.getDefaultMessage(),"no es válido")+".").orElse("Los datos enviados no son válidos.");
    }
    private static String fieldLabel(String field){return switch(field.toLowerCase(Locale.ROOT)){case "email"->"correo electrónico";case "password"->"contraseña";case "username"->"usuario";case "versionname"->"versión";default->"indicado";};}
    private static String integrityMessage(Throwable ex){
        Throwable cause=ex instanceof DataIntegrityViolationException d?d.getMostSpecificCause():ex;
        String detail=Objects.toString(cause.getMessage(),"").toLowerCase(Locale.ROOT);
        if(detail.contains("uk_users_username"))return "El nombre de usuario ya está registrado.";
        if(detail.contains("uk_users_email"))return "El correo electrónico ya está registrado.";
        if(detail.contains("uq_application_versions_code"))return "Esta versión ya está registrada para la aplicación.";
        if(detail.contains("uq_licensed_applications_code")||detail.contains("uq_licensed_applications_package"))return "La aplicación ya está registrada.";
        if(detail.contains("uq_user_application_access")||detail.contains("uk_user_system")||detail.contains("uk_role_permissions"))return "La relación ya está asignada.";
        if(detail.contains("uq_licenses_active_identity"))return "Ya existe una licencia activa para esta aplicación, usuario y dispositivo.";
        return "Existe un conflicto con los datos enviados.";
    }
    private static String safeMessage(String message,String fallback){
        if(message==null||message.isBlank()||message.length()>350||message.matches("(?is).*(\\bselect\\s|\\binsert\\s+into|\\bupdate\\s+\\w+\\s+set|\\bdelete\\s+from|unknown column|duplicate entry|foreign key constraint|jdbc:|password_hash|stacktrace|\\$argon2|\\$2[aby]\\$|bearer\\s|[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}).*"))return fallback;
        return message;
    }
    private static Throwable sanitized(Throwable cause,int depth){
        String message=Objects.toString(cause.getMessage(),"").replaceAll("'(?:''|\\\\.|[^'])*'|\"(?:\\\\.|[^\"])*\"","'[oculto]'")
            .replaceAll("\\$argon2id\\$[^\\s'\\\"]+|\\$2[aby]\\$[^\\s'\\\"]+","[hash oculto]")
            .replaceAll("(?i)Bearer\\s+[^\\s'\\\"]+","Bearer [oculto]")
            .replaceAll("[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}","[JWT oculto]")
            .replaceAll("(?i)(password|password_hash|token|secret|authorization)\\s*[:=]\\s*[^\\s,;]+","$1=[oculto]");
        var safe=new RuntimeException(cause.getClass().getName()+": "+message);safe.setStackTrace(cause.getStackTrace());
        if(depth<16&&cause.getCause()!=null&&cause.getCause()!=cause)safe.initCause(sanitized(cause.getCause(),depth+1));
        for(Throwable suppressed:cause.getSuppressed())if(depth<16&&suppressed!=cause)safe.addSuppressed(sanitized(suppressed,depth+1));
        return safe;
    }
}
