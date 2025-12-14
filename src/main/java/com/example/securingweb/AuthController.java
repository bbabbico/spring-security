package com.example.securingweb;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;

    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public void login(@RequestParam String username,
                               @RequestParam String password,
                               HttpServletResponse response) throws IOException {

        // 1) 아이디/비번 인증 (내부적으로 ProviderManager/DaoAuthenticationProvider 등 사용)
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        // 2) JWT 클레임 구성
        Instant now = Instant.now(); //절대 시간 반환
        
        List<String> roles = auth.getAuthorities().stream() //ROLE 추출
                .map(GrantedAuthority::getAuthority)
                .map(a -> a.startsWith("ROLE_") ? a.substring(5) : a) // "LOOT" 형태로 저장
                .toList();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")                                         // 토큰 발급자
                .issuedAt(now)                                          // 토큰 발급 시간
                .expiresAt(now.plus(1, ChronoUnit.HOURS))   // 토큰 만료 시간
                .subject(auth.getName())                                // 토큰 사용자 - principle의 username/loginId 같은것
                .claim("roles", roles)                            // 위에서 JwtGrantedAuthoritiesConverter 가 ROLE_ 붙여줌
                .build();

        // 3) 서명해서 토큰 쿠키로 발급
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build(); //HS256 으로 인코딩 해서 보내줌.
        String token = jwtEncoder.encode(JwtEncoderParameters.from(header,claims)).getTokenValue();

        ResponseCookie cookie = ResponseCookie.from("ACCESS_TOKEN", token)
                .httpOnly(true)
                .path("/")
                .sameSite("Lax")
                // .secure(true) // https면 켜기
                .maxAge(Duration.ofHours(1))
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        response.sendRedirect("/hello"); // 사이트 리다리렉트
    }
}