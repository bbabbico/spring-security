package com.example.securingweb;

import com.example.securingweb.member.MemberRepository;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;


@Slf4j
@Configuration
@EnableWebSecurity //스프링 시큐리티 관리선언
@RequiredArgsConstructor
public class WebSecurityConfig {

	/** 폼 방식
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { //시큐리티 필터 설정
		http
			.authorizeHttpRequests((requests) -> requests 									//authorizeHttpRequests HTTP 요청에 대한 시큐리티 설정
				.requestMatchers("/", "/home","/login","/join").permitAll() 									// 보안 인증 제외 url  //hasRole() 특정 Role만 허용 // .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER") 처럼 여러 Role 허용
					.requestMatchers("/admin").hasRole("LOOT")
					.anyRequest().authenticated() 																		//anyRequest - requestMatchers 로 설정하지 않은 다른 접근에 대한 설정. //authenticated 로그인된 사용자만 접근 허용
			)
			.formLogin((form) -> form 														//로그인 페이지 매핑
				.loginPage("/login") 																					//로그인 페이지 templates/ 경로로 지정
//					.loginProcessingUrl("/login") 로그인 서비스를 실행할 url - 이 url로 로그인 폼을 보내면 시큐리티가 받아서 인증/인가 과정이 시작됨. 기본값으로 /login 로 되어있음.
					.defaultSuccessUrl("/hello") //로그인 성공시 / 페이지로 리다이렉트
							.permitAll() //모든 사용자 접근 허용
			).logout((logout) -> logout.permitAll()) 											//뒤에 permitAll 붙여서 requestMachers 에 url 추가 안해도됨.
						//logout.logoutUrl("/my/logout/uri") logout.logoutSuccessUrl("/my/success/endpoint") 로그아웃 엔드포인트 지정
				.exceptionHandling(ex -> ex.accessDeniedHandler(customAccessDeniedHandler())) //권한 오류 헨들링
				.sessionManagement(sm -> sm 										//세션 설정
						.maximumSessions(1) 																			//하나의 아이디에 대한 다중 로그인 허용 개수
						.maxSessionsPreventsLogin(true) 																//다중 로그인 허용 개수 초과시 처리 방법 // true : 새로운 로그인 차단 // false : 기존 세션 하나 삭제
				);

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
	**/




	// OAuth 소셜 로그인 github
	@Bean
	@Order(1)
	public SecurityFilterChain securityFilterChainOAuth(HttpSecurity http , OAuth2JwtSuccessHandler oAuth2JwtSuccessHandler) throws Exception {
        http.securityMatcher("/oauth2/**", "/login/oauth2/**") //로그인 요청 허용
				.authorizeHttpRequests(a -> a.anyRequest().permitAll())
				.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
				.csrf(AbstractHttpConfigurer::disable)
				.oauth2Login(o -> o
						.loginPage("/login")
						.userInfoEndpoint(u -> u.userService(githubOAuth2UserService())) // OAuth2 로그인 성공 이후 사용자 정보를 가져올 때의 설정
						.successHandler(oAuth2JwtSuccessHandler) // 로그인 성공 → JWT 쿠키 발급
				);
		return http.build();

	}

	// JWT 방식
	@Bean
	@Order(2)
	public SecurityFilterChain securityFilterChainJWT(HttpSecurity http) throws Exception {

		http
				// JWT면 보통 세션을 안 씀 (기존 maximumSessions/sessionFixation은 의미 없어짐)
				.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.csrf(AbstractHttpConfigurer::disable) //CSRF 미사용

				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/", "/home", "/join", "/login","/favicon.ico").permitAll()
						.requestMatchers("/admin").hasRole("LOOT")
						.anyRequest().authenticated()
				)

				//  Bearer 토큰 검증 파이프라인: BearerTokenAuthenticationFilter → JwtDecoder
				.oauth2ResourceServer(oauth2 -> oauth2
						.bearerTokenResolver(bearerTokenResolver())
						.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
				)

				//  401/403 메시지 처리 (Bearer는 EntryPoint가 WWW-Authenticate도 세팅 가능)
				.exceptionHandling(ex -> ex
						//  로그인 안 했으면 로그인 페이지로
						.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
						//  로그인은 했는데 권한 없으면 403 → error/403.html로 보여주기
						.accessDeniedHandler((req, res, e) -> res.sendError(403))
						.accessDeniedHandler(customAccessDeniedHandler())
				);
		http.logout(logout -> logout //로그아웃 설정 //로그아웃은 get(/logout) 요청이 오면 시큐리티의 기본 LogoutFilter 이 로그아웃 로직을 가로채기 때문에 로그아웃 필터 설정을 해줘야함 아니면 그냥 api/logout 이런식으로 url을 바꿔야함.
				.logoutUrl("/logout")
				.logoutSuccessHandler((req, res, auth) -> {
					ResponseCookie cookie = ResponseCookie.from("ACCESS_TOKEN", "")
							.httpOnly(true)
							.path("/")
							.sameSite("Lax")
							.maxAge(0)
							.build();
					res.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
					res.sendRedirect("/login");
				})
				.permitAll()
		);

		return http.build();
	}

	//  로그인에서 AuthenticationManager를 직접 쓰기 위해 꺼내오는 방식
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}

	// ===== JWT 발급/검증에 필요한 Encoder/Decoder =====

	@Bean
	public SecretKey jwtSecretKey(@Value("${jwt.secret}") String base64Secret) {
		byte[] keyBytes = Base64.getDecoder().decode(base64Secret);
		return new SecretKeySpec(keyBytes, "HmacSHA256");
	}

	// NimbusJwtEncoder: JWT “발급” (서명해서 compact JWT 생성)
	@Bean
	public JwtEncoder jwtEncoder(SecretKey secretKey) {
		return new NimbusJwtEncoder(new ImmutableSecret<>(secretKey));
	}

	// NimbusJwtDecoder: JWT “검증” (서명/클레임 검사 후 Jwt로 decode)
	@Bean
	public JwtDecoder jwtDecoder(SecretKey secretKey) {
		return NimbusJwtDecoder.withSecretKey(secretKey)
				.macAlgorithm(MacAlgorithm.HS256)
				.build();
	}

	// roles 클레임 → ROLE_ 권한으로 변환 (prefix 설정 가능)
	@Bean
	public JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtGrantedAuthoritiesConverter gac = new JwtGrantedAuthoritiesConverter();
		gac.setAuthoritiesClaimName("roles"); // 우리가 발급할 때 roles 넣을 거임
		gac.setAuthorityPrefix("ROLE_");

		JwtAuthenticationConverter jac = new JwtAuthenticationConverter();
		jac.setJwtGrantedAuthoritiesConverter(gac);
		return jac;
	}

	@Bean
	public AccessDeniedHandler customAccessDeniedHandler() {
		return (request, response, accessDeniedException) -> {
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.setContentType("text/plain;charset=UTF-8");
			response.getWriter().write("잘못된 접근입니다.");
		};
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public BearerTokenResolver bearerTokenResolver() {
		return request -> {
			// 1) Authorization 헤더 우선
			String auth = request.getHeader("Authorization");
			if (auth != null && auth.startsWith("Bearer ")) {
				return auth.substring(7);
			}
			// 2) 없으면 쿠키에서
			Cookie[] cookies = request.getCookies();
			if (cookies == null) return null;
			for (Cookie c : cookies) {
				if ("ACCESS_TOKEN".equals(c.getName())) {
					return c.getValue();
				}
			}
			return null;
		};
	}

	@Bean
	public OAuth2UserService<OAuth2UserRequest, OAuth2User> githubOAuth2UserService() {
		DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

		return userRequest -> {
			OAuth2User user = delegate.loadUser(userRequest);
			Map<String, Object> attrs = new HashMap<>(user.getAttributes());

			if (attrs.get("email") == null) {
				String accessToken = userRequest.getAccessToken().getTokenValue();
				log.info("이메일 null임");

				// /user/emails 호출해서 primary email 뽑기 (WebClient/RestClient 아무거나 OK)
				// (구현 디테일은 프로젝트 스타일에 맞추면 됨)
			}

			// name이 null이면 login으로 대체
			if (attrs.get("name") == null) attrs.put("name", attrs.get("login"));

			// GitHub는 user-name-attribute로 어떤 키를 "name"으로 쓸지 정함(보통 login/id 중 선택)
			return new DefaultOAuth2User(user.getAuthorities(), attrs, "login");
		};
	}
}
