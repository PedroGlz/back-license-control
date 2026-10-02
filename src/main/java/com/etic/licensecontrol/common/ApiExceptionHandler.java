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
    @ExceptionHandler(Exception.class)
    ResponseEntity<Map<String,Object>> handle(Exception ex, HttpServletRequest req) {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String message = "Ocurrió un error inesperado";
        if (ex instanceof ResponseStatusException r) { status = HttpStatus.valueOf(r.getStatusCode().value()); message = r.getReason(); }
        else if (ex instanceof MethodArgumentNotValidException v) { status = HttpStatus.BAD_REQUEST; message = v.getBindingResult().getFieldErrors().stream().findFirst().map(e -> e.getField()+": "+e.getDefaultMessage()).orElse("Datos inválidos"); }
        else if (ex instanceof IllegalArgumentException) { status = HttpStatus.BAD_REQUEST; message = ex.getMessage(); }
        else if (ex instanceof DataIntegrityViolationException) { status = HttpStatus.CONFLICT; message = "El registro está duplicado o referenciado"; }
        else if(ex instanceof org.springframework.web.multipart.MaxUploadSizeExceededException){status=HttpStatus.PAYLOAD_TOO_LARGE;message="El APK excede el tamaño máximo permitido";}
        Map<String,Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now()); body.put("status", status.value()); body.put("error", status.getReasonPhrase()); body.put("message", message); body.put("path", req.getRequestURI());
        return ResponseEntity.status(status).body(body);
    }
}
