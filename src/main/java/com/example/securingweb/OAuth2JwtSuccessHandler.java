package com.example.securingweb;

import com.example.securingweb.member.Member;
import com.example.securingweb.member.MemberRepository;
import com.example.securingweb.member.Role;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class OAuth2JwtSuccessHandler implements AuthenticationSuccessHandler {
    private final MemberRepository memberRepository;
    private final JwtService jwtService;

    @Override // JWT 생성
    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse res, Authentication auth) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) auth.getPrincipal();

        String email = (String) oAuth2User.getAttributes().get("email");
        String name  = (String) oAuth2User.getAttributes().get("name");
        Object idObj = oAuth2User.getAttributes().get("id");      // GitHub numeric id
        String login = (String) oAuth2User.getAttributes().get("login"); // GitHub username

        // 1) 필수값 보정
        if (name == null) name = login;
        if (email == null) {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "GitHub email 정보를 가져올 수 없습니다. (scope user:email, primary email 설정 확인)");
            return;
        }

        // 안정적인 로그인 식별자(추천: github_id 기반)
        String loginId = (idObj != null) ? "github_" + idObj : "github_" + login;

        // 2) Member 매핑/저장 (email 기준)
        String finalName = name; //임시
        Member member = memberRepository.findByEmail(email).orElseGet(() -> {
            Member m = new Member();
            m.setEmail(email);
            m.setName(finalName);
            m.setRole(Role.USER);

            // 엔티티가 nullable=false라서 반드시 채워야 함
            m.setLoginId(loginId);
            m.setPassword("github+"+finalName); // 더미 비번
            return m;
        });

        // 기존회원이면 기본정보 업데이트(선택)
        member.setEmail(email);
        member.setName(name);

        // 기존 데이터에 loginId/role/password가 비어있으면 다시 저장
        if (member.getLoginId() == null || member.getLoginId().isBlank()) {
            member.setLoginId(loginId);
        }
        if (member.getRole() == null) {
            member.setRole(Role.USER);
        }
        if (member.getPassword() == null || member.getPassword().isBlank()) {
            member.setPassword("github+"+name); // 폼 로그인으로는 DB 에 저장된 github 계정 로그인 불가
        }

        memberRepository.save(member);

        // 3) JWT 발급을 위해 "ROLE_USER" 권한을 가진 Authentication을 하나 만들어 JwtService에 전달 (JwtService 가 Authentication 을 파라미터로 받음)
        List<GrantedAuthority> authorities =
                List.of(new SimpleGrantedAuthority("ROLE_" + member.getRole().name()));

        Authentication tokenAuth =
                new UsernamePasswordAuthenticationToken(member.getLoginId(), null, authorities);

        ResponseCookie cookie = jwtService.Jwt(tokenAuth);
        res.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        // 4) 성공 후 이동
        res.sendRedirect("/hello");
    }
}
