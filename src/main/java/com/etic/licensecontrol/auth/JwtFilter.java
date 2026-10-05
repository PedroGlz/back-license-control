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
    JwtFilter(JwtService jwt, AuthRepository users){this.jwt=jwt;this.users=users;}
    protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws ServletException,IOException{
        String h=req.getHeader("Authorization"); String id=h!=null&&h.startsWith("Bearer ")?jwt.subject(h.substring(7)):null;
        if(id!=null&&"LICENSE_CONTROL".equals(jwt.system(h.substring(7)))&&users.isAuthorized(id)) SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(id,null,List.of()));
        chain.doFilter(req,res);
    }
}
