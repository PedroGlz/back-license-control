package com.etic.licensecontrol.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtFilter extends OncePerRequestFilter {
    private final JwtService jwt; private final AuthRepository users;
    private final org.springframework.web.servlet.HandlerExceptionResolver errors;
    JwtFilter(JwtService jwt, AuthRepository users,@org.springframework.beans.factory.annotation.Qualifier("handlerExceptionResolver") org.springframework.web.servlet.HandlerExceptionResolver errors){this.jwt=jwt;this.users=users;this.errors=errors;}
    protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws ServletException,IOException{
        try {
        String h=req.getHeader("Authorization");String token=h!=null&&h.startsWith("Bearer ")?h.substring(7):null;String id=token==null?null:jwt.subject(token);
        String system=id==null?null:jwt.system(token);String purpose=id==null?null:jwt.purpose(token);
        int tokenVersion=id==null?-1:jwt.authVersion(token),currentVersion=id==null?-2:users.authVersion(id);
        boolean versionValid=tokenVersion<0?currentVersion==0:tokenVersion==currentVersion;
        boolean routeAllowed=!"PASSWORD_CHANGE".equals(purpose)||"/api/auth/required-password".equals(req.getRequestURI());
        if(id!=null&&system!=null&&versionValid&&routeAllowed&&users.isAuthorized(id,system)){
            var authentication=new UsernamePasswordAuthenticationToken(id,null,List.of());
            authentication.setDetails(system);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        }catch(Exception ex){errors.resolveException(req,res,null,ex);return;}
        chain.doFilter(req,res);
    }
}
