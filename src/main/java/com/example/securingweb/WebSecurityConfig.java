package com.example.securingweb;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity //스프링 시큐리티 관리선언
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { //시큐리티 필터 설정
		http
			.authorizeHttpRequests((requests) -> requests //authorizeHttpRequests HTTP 요청에 대한 시큐리티 설정 
				.requestMatchers("/", "/home").permitAll() // 보안 인증 제외 url  //hasRole() 특정 Role만 허용 // .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER") 처럼 여러 Role 허용
				.anyRequest().authenticated() //anyRequest - requestMatchers 로 설정하지 않은 다른 접근에 대한 설정. //authenticated 로그인된 사용자만 접근 허용
			)
			.formLogin((form) -> form //로그인 페이지 매핑
				.loginPage("/login") //로그인 페이지 templates/ 경로로 지정
//					.loginProcessingUrl("/login") 로그인 서비스를 실행할 url - 이 url로 로그인 폼을 보내면 인증/인가 과정이 시작됨. 기본값으로 /login 로 되어있음.
				.permitAll() //모든 사용자 접근 허용
			)
			.logout((logout) -> logout.permitAll());

		return http.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		UserDetails user =
			 User.builder()
				.username("user")
				.password(encoder.encode("password"))
				.roles("USER")
				.build();

		return new InMemoryUserDetailsManager(user);
	}
}
