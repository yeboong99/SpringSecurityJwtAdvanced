package com.example.springsecurityjwtbasic.jwt;

import com.example.springsecurityjwtbasic.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Iterator;

// 로그인 시 거칠 필터 설정. 기존 UsernamepasswordAuthenticationFilter는 FormLogin방식이 disable되면서 함께 비활성화되어버림.
// 이를 대체해줄 UsernamePasswordAuthenticationFilter를 직접 커스텀해서 달아줘야함.
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    // 받은 요청을 뜯어서 username과 password를 authentication token에 담아 AuthenticationManager에게 보내주는 메서드
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 클라이언트 요청에서 username과 password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println(username);

        // Spring Security에서 username과 password를 검증하기 위해서는 token에 담아야 함. AuthenticationManager를 위한 DTO라고 보면 됨.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // token에 담아 검증을 위한 AuthenticationManager로 전달. 전달받을 AuthenticationManager는 이 클래스 상단에 주입해줬음.
        return authenticationManager.authenticate(authToken);
    }

    // 로그인 성공 시 실행하는 메서드 (여기서 JWT를 발급하게 될거임.)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, Authentication authentication) throws AuthenticationException {
        // Authentication 객체 정보를 통해 유저 가져오기
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        // username 가져오기
        String username = customUserDetails.getUsername();
        // role 가져오는 과정
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        // 토큰 생성하기
        String token = jwtUtil.createJwt(username, role, 60*60*10L);

        // 헤더에 발급된 토큰 넣어주기
        response.addHeader("Authorization", "Bearer " + token);
    }

    // 로그인 실패 시 실행하는 메서드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

        System.out.println("failed");
    }


}
