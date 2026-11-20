package com.etic.licensecontrol.auth;

import org.springframework.http.HttpStatus;

public final class LoginDeniedException extends RuntimeException {
    private final HttpStatus status;
    private final String code;
    private final String userId;
    private final String system;

    LoginDeniedException(HttpStatus status, String code, String message, String userId, String system) {
        super(message);
        this.status = status;
        this.code = code;
        this.userId = userId;
        this.system = system;
    }

    public HttpStatus status() { return status; }
    public String code() { return code; }
    public String userId() { return userId; }
    public String system() { return system; }
}
