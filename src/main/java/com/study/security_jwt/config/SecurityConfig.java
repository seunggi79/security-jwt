package com.study.security_jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // 스프링 설정 클래스
@EnableWebSecurity // 웹 보안 설정을 활성화
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //csrf disable
        http
                .csrf((auth) -> auth.disable());

        //From 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        // ⭐ H2 콘솔은 iframe을 쓰므로 frameOptions를 풀어야 함
        http.headers(headers -> headers.frameOptions(frame -> frame.disable()));

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        // ⭐ H2 콘솔 경로 허용
                        .requestMatchers("/", "/login", "/join", "/h2-console/**").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()); // 위에서 허용한 경로 외에는 로그인(인증)되어야 접근 가능

        //세션 설정
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // 세션 사용 안함

        return http.build();
    }
}