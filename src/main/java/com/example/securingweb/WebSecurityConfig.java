package com.example.securingweb;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
@EnableWebSecurity //스프링 시큐리티 관리선언
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { //시큐리티 필터 설정
		http
			.authorizeHttpRequests((requests) -> requests //authorizeHttpRequests HTTP 요청에 대한 시큐리티 설정 
				.requestMatchers("/", "/home","/login","/join").permitAll() // 보안 인증 제외 url  //hasRole() 특정 Role만 허용 // .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER") 처럼 여러 Role 허용
					.requestMatchers("/admin").hasRole("LOOT")
					.anyRequest().authenticated() //anyRequest - requestMatchers 로 설정하지 않은 다른 접근에 대한 설정. //authenticated 로그인된 사용자만 접근 허용
			)
			.formLogin((form) -> form //로그인 페이지 매핑
				.loginPage("/login") //로그인 페이지 templates/ 경로로 지정
//					.loginProcessingUrl("/login") 로그인 서비스를 실행할 url - 이 url로 로그인 폼을 보내면 시큐리티가 받아서 인증/인가 과정이 시작됨. 기본값으로 /login 로 되어있음.
					.defaultSuccessUrl("/hello") //로그인 성공시 / 페이지로 리다이렉트
							.permitAll() //모든 사용자 접근 허용
			).logout((logout) -> logout.permitAll()); //뒤에 permitAll 붙여서 requestMachers 에 url 추가 안해도됨.
			//logout.logoutUrl("/my/logout/uri") logout.logoutSuccessUrl("/my/success/endpoint") 로그아웃 엔드포인트 지정

		http.exceptionHandling(ex -> ex //에러 발생시 설정
//				.accessDeniedPage("/denied")  // 권한 부족시 이 URL로
				.accessDeniedHandler(customAccessDeniedHandler())
		);

		http
				.sessionManagement((auth) -> auth //세션 설정
						.maximumSessions(1) //하나의 아이디에 대한 다중 로그인 허용 개수
						.maxSessionsPreventsLogin(true)); //다중 로그인 허용 개수 초과시 처리 방법 // true : 새로운 로그인 차단 // false : 기존 세션 하나 삭제

		http
				.sessionManagement((auth) -> auth //세션 고정 공격 보호
						.sessionFixation()
						.none()); //로그인 시 세션 정보 변경 안함
						//.newSession()); //로그인 시 세션 새로 생성
						//.changeSessionId()); //로그인 시 동일한 세션에 대한 id 변경



		return http.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() { // 시큐리티에서 사용할 비밀번호 인코더, 회원가입 로그인 둘다 동일한 포맷을 사용해야 됨. AuthenticationManager 가 내부적으로 회원 인증을 할때 사용하므로 무조건 있어야함.
		return new BCryptPasswordEncoder();
	}

	@Bean
	public RoleHierarchy roleHierarchy() { // ROLE 계층을 나눔. 상위 계층 사용자는 자동으로 하위계층 권한이 붙여짐.
		return RoleHierarchyImpl.fromHierarchy("ROLE_LOOT > ROLE_USER\n" + "ROLE_B > ROLE_A");
	}

	@Bean
	public AccessDeniedHandler customAccessDeniedHandler() { // 원래 권한 오류나면 accessDeniedPage 로 페이지 이동하는데 json 이나 메시지를 그냥 출력하는거면 직접 설정해줘야함.
		return (request, response, accessDeniedException) -> { //response.sendError(403, "Access Denied"); 내부적으로 이렇게 동작하기 때문에 src/main/resources/templates/error/403.html 이런식으로 그냥 파일 추가만 해도됨.
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.setContentType("text/plain;charset=UTF-8");
			response.getWriter().write("잘못된 접근입니다.");
		};
	}
}
