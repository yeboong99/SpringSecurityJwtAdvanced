package com.example.springsecurityjwtbasic.jwt;

import com.example.springsecurityjwtbasic.domain.Refresh;
import com.example.springsecurityjwtbasic.repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

// 로그인 시 거칠 필터 설정. 기존 UsernamepasswordAuthenticationFilter는 FormLogin방식이 disable되면서 함께 비활성화되어버림.
// 이를 대체해줄 UsernamePasswordAuthenticationFilter를 직접 커스텀해서 달아줘야함.
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

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

    // 로그인 성공 시 실행하는 메서드 (Access token, Refresh token 두 개를 발급한다.)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, Authentication authentication) throws AuthenticationException {

        // 1. 유저 정보를 꺼내온다.
        String username = authentication.getName();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority authority = iterator.next();
        String role = authority.getAuthority();

        // 2. 토큰 두 개를 발급한다. 하나는 accsess, 하나는 refresh라는 이름으로 발급한다.
        String access = jwtUtil.createJwt("access", username, role, 600000L);   // 10분
        String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L);   // 1일

        // 2.5. 생성한 Refresh토큰 db에 저장
        addRefreshEntity(username, refresh, 86400000L);

        // 3. 응답 생성
        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));   // 아래 정의되어 있음.
        response.setStatus(HttpStatus.OK.value());
    }

    // 로그인 실패 시 실행하는 메서드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

        System.out.println("failed");
    }

    // 쿠키 생성해주는 메서드
    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60); // 86400초 -> 1일. 쿠키 만료시간은 ms아님. 초임.
//        cookie.setSecure(true);   // https통신을 이용할 경우 활성화하면 됨. HTTPS통신에서만 쿠키를 전송하도록 하는 설정. https로 통신을 하지 않는데 활성화시키면 쿠키가 전송되지 않음.
//        cookie.setPath("/");      // 쿠키가 적용될 범위 설정 가능. 쿠키가 특정 경로 또는 하위 경로에서만 전송되도록 제한할 수 있음.
        cookie.setHttpOnly(true);   // XSS(자바스크립트 공격)로부터 방어하기 위한 HttpOnly 옵션 켜기 (필수적으로 해주자!) 브라우저의 JavaScript 코드로 쿠키에 접근하지 못하도록 막아준다.

        return cookie;
    }

    // 새 refresh정보 db에 저장해주는 메서드
    private void addRefreshEntity(String username, String refresh, Long expiredMs) {
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        Refresh refreshEntity = new Refresh();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

}
