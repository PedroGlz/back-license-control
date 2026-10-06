package com.etic.licensecontrol.config;

import com.etic.licensecontrol.auth.JwtFilter;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {
    @Bean PasswordEncoder passwordEncoder() { return new MigrationPasswordEncoder(); }
    @Bean CorsConfigurationSource cors(@Value("${license-control.frontend-origin}") String origin) {
        CorsConfiguration c = new CorsConfiguration(); c.setAllowedOrigins(java.util.Arrays.stream(origin.split(",")).map(String::trim).filter(s->!s.isEmpty()).toList()); c.setAllowedMethods(List.of("GET","POST","PUT","PATCH","DELETE","OPTIONS")); c.setAllowedHeaders(List.of("Authorization","Content-Type"));
        UrlBasedCorsConfigurationSource s = new UrlBasedCorsConfigurationSource(); s.registerCorsConfiguration("/**", c); return s;
    }
    @Bean SecurityFilterChain security(HttpSecurity http, JwtFilter jwt, @org.springframework.beans.factory.annotation.Qualifier("cors") CorsConfigurationSource source) throws Exception {
        return http.csrf(c -> c.disable()).cors(c -> c.configurationSource(source)).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(e -> e.authenticationEntryPoint((req,res,ex)->com.etic.licensecontrol.common.ApiExceptionHandler.write(req,res,org.springframework.http.HttpStatus.UNAUTHORIZED,"Tu sesión no es válida o expiró."))
                .accessDeniedHandler((req,res,ex)->com.etic.licensecontrol.common.ApiExceptionHandler.write(req,res,org.springframework.http.HttpStatus.FORBIDDEN,"El usuario no tiene permiso para realizar esta operación.")))
            .authorizeHttpRequests(a -> a.requestMatchers(HttpMethod.POST,"/api/auth/login","/api/auth/system-login").permitAll().requestMatchers("/api/system/health").permitAll()
                .requestMatchers(HttpMethod.POST,"/api/mobile/device/enroll","/api/mobile/device/*/challenge","/api/mobile/device/*/verify","/api/mobile/device/*/validate","/api/mobile/device/*/refresh").permitAll()
                .requestMatchers("/api/auth/me").authenticated()
                .requestMatchers("/api/admin/**").access((auth,context)->new org.springframework.security.authorization.AuthorizationDecision(auth.get().isAuthenticated()&&"LICENSE_CONTROL".equals(auth.get().getDetails())))
                .requestMatchers("/api/portal/**").access((auth,context)->new org.springframework.security.authorization.AuthorizationDecision(auth.get().isAuthenticated()&&"ETIC_SUITE".equals(auth.get().getDetails())))
                .anyRequest().denyAll())
            .addFilterBefore(jwt, UsernamePasswordAuthenticationFilter.class).build();
    }
    @Bean org.springframework.security.core.userdetails.UserDetailsService userDetailsService(){return new org.springframework.security.provisioning.InMemoryUserDetailsManager(java.util.Collections.emptyList());}
}
