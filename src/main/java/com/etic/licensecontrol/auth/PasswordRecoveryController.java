package com.etic.licensecontrol.auth;
import java.util.*;import org.springframework.security.core.Authentication;import org.springframework.web.bind.annotation.*;
@RestController public class PasswordRecoveryController {
 private final PasswordRecoveryService service;PasswordRecoveryController(PasswordRecoveryService service){this.service=service;}
 record Request(String identifier,String system){} record Reset(String userId,String requestId){} record Delivery(String deliveryToken){}
 @PostMapping("/api/auth/password-reset-requests") Map<String,Object> request(@RequestBody Request body){return service.request(body.identifier(),body.system());}
 @GetMapping("/api/admin/password-reset-requests") List<Map<String,Object>> list(Authentication auth){return service.list(auth);}
 @PostMapping("/api/admin/password-reset-requests/reset") Map<String,Object> reset(@RequestBody Reset body,Authentication auth){return service.reset(body.userId(),body.requestId(),auth);}
 @PostMapping("/api/admin/password-reset-requests/notify") Map<String,Object> notify(@RequestBody Delivery body,Authentication auth){return service.notifyUser(body.deliveryToken(),auth);}
 @PutMapping("/api/admin/password-reset-requests/{id}/reject") void reject(@PathVariable String id,Authentication auth){service.reject(id,auth);}
}
