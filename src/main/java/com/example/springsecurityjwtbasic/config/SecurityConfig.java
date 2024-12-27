package com.example.springsecurityjwtbasic.config;

import com.example.springsecurityjwtbasic.jwt.JWTFilter;
import com.example.springsecurityjwtbasic.jwt.JWTUtil;
import com.example.springsecurityjwtbasic.jwt.LoginFilter;
import com.example.springsecurityjwtbasic.repository.RefreshRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collection;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // AuthenticationManager가 인자로 받을 AuthenticationConfiguration 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        // cors 설정 : 교차 출처 자원 공유(Cross-origin resource sharing) 방지에 대한 설정
        // 두 가지 설정이 필요함. 하나는 시큐리티 필터체인을 통과해야하는 요청에 대한 cors 설정, 하나는 백엔드 서버로 들어오는 요청에 대한 cors설정. 전자는 여기(SecurityConfig)에서, 후자는 CorsMvcConfig에서 설정.
        // 여기서 설정한 cors는 아래 통과하는 필터들에 대한 cors 해방을 시켜주는거임. 다른 컨트롤러 단에서의 cors는 CorsMvcConfig에서 처리하자.
        http
                .cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();
                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));    // 프론트 서버가 react라는 가정
                        configuration.setAllowedMethods(Collections.singletonList("*"));    // GET, POST, ... 등 모든 메서드에 대한 요청 허용
                        configuration.setAllowCredentials(true);    // 인증 정보(쿠키, 인증 헤더(Authorization), SSL 인증서 등의 민감한 데이터)를 포함한 요청을 허용할 것인지에 대한 설정.
                        configuration.setAllowedHeaders(Collections.singletonList("*"));    // 클라이언트가 서버로 보낼 수 있는 헤더에 대한 설정. 여기서는 모든 헤더 허용
                        configuration.setMaxAge(3600L); // CORS 설정을 캐싱할 시간을 설정. 클라이언트가 사전 요청(OPTIONS 요청)을 다시 보내기 전에 CORS 설정을 캐싱할 시간. 여기서는 1시간.
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));    // 클라이언트가 응답 헤더에서 접근할 수 있는 헤더 목록을 설정. 여기서는 Authorization 헤더를 클라이언트가 접근할 수 있도록 허용.

                        return configuration;
                    }
                })));

        // csrf 비활성화 : 세션 방식에서는 세션 고정 보안을 설정해야해서 필요하지만, jwt에서는 필요하지 않음. (세션 방식이 아님)
        http
                .csrf((auth) -> auth.disable());

        // Form로그인, httpBasic인증 방식도 마찬가지.
        http
                .formLogin((auth) -> auth.disable());
        http
                .httpBasic((auth) -> auth.disable());

        // 각 경로 별 인가 설정 : authorizeHttpRequests()
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasAnyRole("ADMIN")
                        .requestMatchers("/reissue").permitAll()    // access 토큰 재발급 경로를 모든 사용자가 접근 가능하도록 설정 추가 (access token이 만료된 상태이므로 로그인 이후 사용가능한 모든 요청이 정상적으로 처리되지 않는다. 토큰 재발급 경로는 모두가 접근할 수 있어야 한다.)
                        .anyRequest().authenticated()); // 그 외 나머지 경로에는(anyRequest()) 로그인 한 사용자만 접근 가능(authenticated())

        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);   // jwt 필터 위치는 login필터 앞
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, refreshRepository), UsernamePasswordAuthenticationFilter.class);

        // 세션을 STATELESS로 설정 !!가장 중요!!
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

}
