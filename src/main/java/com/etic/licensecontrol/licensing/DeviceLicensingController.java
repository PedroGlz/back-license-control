package com.etic.licensecontrol.licensing;

import java.util.*;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
public class DeviceLicensingController {
    private final DeviceLicensingService service;
    public DeviceLicensingController(DeviceLicensingService service) { this.service=service; }
    @PostMapping("/api/mobile/device/enroll")
    ResponseEntity<?> enroll(@RequestBody DeviceLicensingService.Enrollment body) { return response(service.enroll(body)); }
    @PostMapping("/api/mobile/device/{deviceId}/challenge")
    ResponseEntity<?> challenge(@PathVariable String deviceId,@RequestBody DeviceLicensingService.Proof body) { return response(service.challenge(deviceId,body.licenseId())); }
    @PostMapping("/api/mobile/device/{deviceId}/{action:verify|validate|refresh}")
    ResponseEntity<?> verify(@PathVariable String deviceId,@PathVariable String action,@RequestBody DeviceLicensingService.Proof body) { return response(service.validate(deviceId,body,action)); }
    @GetMapping("/api/admin/enrollment-codes")
    ResponseEntity<?> codes() { return response(service.codes()); }
    @PostMapping("/api/admin/enrollment-codes")
    ResponseEntity<?> generate(@RequestBody DeviceLicensingService.Activation body,Authentication auth) { return response(service.generate(body,auth.getName())); }
    private static ResponseEntity<?> response(Object value) { return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(value); }
    @ExceptionHandler(org.springframework.web.server.ResponseStatusException.class)
    ResponseEntity<?> denied(org.springframework.web.server.ResponseStatusException ex) {
        if(ex.getStatusCode().is5xxServerError())org.slf4j.LoggerFactory.getLogger(DeviceLicensingController.class).error("No fue posible emitir la credencial offline",ex);
        String reason=Objects.toString(ex.getReason(),"Operación no disponible");
        int separator=reason.indexOf(':');String code=separator>0?reason.substring(0,separator):"ACCESS_DENIED";
        if(!Set.of("LICENSE_SUSPENDED","LICENSE_REVOKED","LICENSE_EXPIRED","DEVICE_REVOKED","NO_SEATS_AVAILABLE").contains(code))code="ACCESS_DENIED";
        return ResponseEntity.status(ex.getStatusCode()).cacheControl(CacheControl.noStore()).body(Map.of("allowed",false,"code",code,"message",reason));
    }
}
