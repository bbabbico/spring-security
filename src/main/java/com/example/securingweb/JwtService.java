package com.example.securingweb;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtEncoder jwtEncoder;

    public ResponseCookie Jwt(Authentication auth) {
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
        String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        // .secure(true) // https면 켜기

        return ResponseCookie.from("ACCESS_TOKEN", token)
                .httpOnly(true)
                .path("/")
                .sameSite("Lax")
                // .secure(true) // https면 켜기
                .maxAge(Duration.ofHours(1))
                .build();
    }
}
