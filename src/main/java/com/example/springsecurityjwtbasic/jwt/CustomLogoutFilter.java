package com.example.springsecurityjwtbasic.jwt;

import com.example.springsecurityjwtbasic.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        doFilter((HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse, filterChain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        // 경로, 메서드 확인
        String requestUri = request.getRequestURI();
        if(!requestUri.matches("^\\/logout$")) {    // 만약 경로에 /logout이 없으면
            filterChain.doFilter(request, response);    // 필터 그냥 통과시키고 종료
            return;
        }
        String requestMethod = request.getMethod();
        if (!requestMethod.equals("POST")) {            // 만약 메소드가 POST가 아니면
            filterChain.doFilter(request, response);    // 필터 그냥 통과시키고 종료
            return;
        }

        // refresh 토큰 가져오기
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {   // 요청 쿠키에서 key가 refresh인 것을 찾아 값(순수토큰)을 가져옴
                refresh = cookie.getValue();
            }
        }

        // refresh토큰 null인지 확인
        if (refresh == null) {                                      // 토큰이 없다면
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST); // 400 Bad Request 응답 후 종료
            return;
        }

        // refresh토큰 만료되었는지 확인
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {
            // refresh 토큰이 만료되었으면 400 응답 후 종료
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 추출한 순수 토큰의 category가 refresh인지 확인 (발급 시 payload에 명시되었었음)
        String category = jwtUtil.getCategory(refresh);
        if (!category.equals("refresh")) {
            // category의 값이 refresh가 아니라면 400 응답 후 종료
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 이 refresh 토큰이 db에 저장되어있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {
            // db에 저장된 적이 없는 토큰이라면 400 응답 후 종료
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 여기까지 통과했으면 정상적인 refresh토큰이므로 로그아웃 진행.

        // 기존 refresh 토큰 db에서 제거
        refreshRepository.deleteByRefresh(refresh);

        // refresh토큰의 Cookie 값 null(0)으로 초기화
        Cookie cookie = new Cookie("refresh", null);
        cookie.setMaxAge(0);    // 만료기간도 0으로 초기화
        cookie.setPath("/");    // 기본 경로로 초기화

        // 초기화한 새 쿠키를 응답에 달아준다.
        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);
    }
}
