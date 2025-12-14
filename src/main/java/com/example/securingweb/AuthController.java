package com.example.securingweb;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public void login(@RequestParam String username,
                               @RequestParam String password,
                               HttpServletResponse response) throws IOException {

        // 1) 아이디/비번 인증 (내부적으로 ProviderManager/DaoAuthenticationProvider 등 사용)
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        response.addHeader(HttpHeaders.SET_COOKIE, jwtService.Jwt(auth).toString());
        response.sendRedirect("/hello"); // 사이트 리다리렉트
    }
}