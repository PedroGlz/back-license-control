package com.etic.licensecontrol.common;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class ApiExceptionHandler {
    private static final org.slf4j.Logger log=org.slf4j.LoggerFactory.getLogger(ApiExceptionHandler.class);
    @ExceptionHandler(Exception.class)
    ResponseEntity<Map<String,Object>> handle(Exception ex, HttpServletRequest req) {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String message = "Ocurrió un error inesperado";
        if (ex instanceof ResponseStatusException r) { status = HttpStatus.valueOf(r.getStatusCode().value()); message = r.getReason(); }
        else if (ex instanceof MethodArgumentNotValidException v) { status = HttpStatus.BAD_REQUEST; message = v.getBindingResult().getFieldErrors().stream().findFirst().map(e -> e.getField()+": "+e.getDefaultMessage()).orElse("Datos inválidos"); }
        else if (ex instanceof IllegalArgumentException) { status = HttpStatus.BAD_REQUEST; message = ex.getMessage(); }
        else if (ex instanceof DataIntegrityViolationException integrity) {
            Throwable cause=integrity.getMostSpecificCause();
            int code=cause instanceof java.sql.SQLException sql?sql.getErrorCode():0;
            String detail=java.util.Objects.toString(cause.getMessage(),"");
            var constraint=java.util.regex.Pattern.compile("(?:UK|FK|CK)_[A-Za-z0-9_]+").matcher(detail);
            log.error("Error de integridad en {}: código SQL={}, constraint={}", req.getRequestURI(), code, constraint.find()?constraint.group():"no identificada", sanitized(integrity,0));
            if(code==1062||ex instanceof org.springframework.dao.DuplicateKeyException){
                status=HttpStatus.CONFLICT;
                message=detail.contains("UK_Users_Username")?"El nombre de usuario ya existe":detail.contains("UK_Users_Email")?"El correo electrónico ya está registrado":"Ya existe un registro con estos datos";
            }else if(code==1452&&!detail.contains("FK_AuditEvents_")){
                status=HttpStatus.BAD_REQUEST;
                message=detail.contains("FK_Users_UserType")?"El tipo de usuario no existe o está inactivo":"El registro relacionado no existe";
            }else if(code==1451){
                status=HttpStatus.CONFLICT;message="El registro está referenciado y no puede eliminarse";
            }
        }
        else if(ex instanceof org.springframework.web.multipart.MaxUploadSizeExceededException){status=HttpStatus.PAYLOAD_TOO_LARGE;message="El APK excede el tamaño máximo permitido";}
        if(status==HttpStatus.INTERNAL_SERVER_ERROR&&!(ex instanceof DataIntegrityViolationException))
            log.error("Error interno en {}", req.getRequestURI(), sanitized(ex,0));
        Map<String,Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now()); body.put("status", status.value()); body.put("error", status.getReasonPhrase()); body.put("message", message); body.put("path", req.getRequestURI());
        return ResponseEntity.status(status).body(body);
    }
    private Throwable sanitized(Throwable cause,int depth){
        String message=java.util.Objects.toString(cause.getMessage(),"")
            .replaceAll("'(?:''|\\\\.|[^'])*'","'[oculto]'")
            .replaceAll("\\$argon2id\\$[^\\s'\\\"]+|\\$2[aby]\\$[^\\s'\\\"]+","[hash oculto]")
            .replaceAll("(?i)Bearer\\s+[^\\s'\\\"]+","Bearer [oculto]")
            .replaceAll("[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}","[JWT oculto]")
            .replaceAll("(?i)(password|password_hash|token|secret|authorization)\\s*[:=]\\s*[^\\s,;]+","$1=[oculto]");
        var safe=new RuntimeException(cause.getClass().getName()+": "+message);
        safe.setStackTrace(cause.getStackTrace());
        if(depth<8&&cause.getCause()!=null&&cause.getCause()!=cause)safe.initCause(sanitized(cause.getCause(),depth+1));
        return safe;
    }
}
