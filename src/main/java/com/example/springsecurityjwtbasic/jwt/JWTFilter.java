package com.example.springsecurityjwtbasic.jwt;

import com.example.springsecurityjwtbasic.domain.User;
import com.example.springsecurityjwtbasic.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // request에서 Authorization 헤더를 찾는다.
        String authorization = request.getHeader("Authorization");

        if (authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("token null");
            filterChain.doFilter(request, response); // 이 필터가 받은 request와 response를 이 필터를 수행하지 않고 다음 필터로 그대로 넘겨준다.

            // 만약 토큰이 없거나 Baerer 로 시작하지 않으면 이 메서드를 종료시켜야 한다.(필수)
            return;
        }

        System.out.println("authorization now");
        // Baerer 부분 제거 후 순수 토큰만 가져옴.
        String token = authorization.split(" ")[1];

        // 토큰 소멸시간 검증
        if (jwtUtil.isExpired(token)) {
            System.out.println("token expired");
            filterChain.doFilter(request, response);

            // 만약 토큰이 만료되었으면 이 메서드를 종료시켜야 한다.
            return;
        }

        // 토큰에서 username과 role을 획득한다.
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // 새로운 User를 생성해 값을 넣는다.
        User user = new User();
        user.setUsername(username);
        user.setPassword("temp password");  // 새로운 유저 정보 생성만을 위한 임시 비밀번호. (여기까지 왔다는건 비번 인증을 통과 했다는거니까? 비번을 매번 담아서 옮겨다닐 필요도 없고 db조회 할 필요도 없다)
        user.setRole(role);

        // UserDetails에 회원 정보 객체를 담아준다.
        CustomUserDetails customUserDetails = new CustomUserDetails(user);

        // Spring Security용 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        // Spring Security 세션에 사용자 등록 (유저 세션 생성)
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
