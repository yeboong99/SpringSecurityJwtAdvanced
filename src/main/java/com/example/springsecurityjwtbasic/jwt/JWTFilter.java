package com.example.springsecurityjwtbasic.jwt;

import com.example.springsecurityjwtbasic.domain.User;
import com.example.springsecurityjwtbasic.dto.CustomUserDetails;
import io.jsonwebtoken.ExpiredJwtException;
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
import java.io.PrintWriter;

// 토큰이 만료될 경우 응답되는 상태 코드를 보고 프론트에서 예외처리를 하여 재발급 요청하는 로직을 구현했다고 가정한 경우이다.
// 아래 코드는 만료된 토큰인 경우 재발급을 해주는 로직이 없다. 이는 프론트에서 구현하고,
// 백엔드는 프론트엔드가 재발급 로직을 발동시킬 수 있도록 프론트엔드가 원하는 상태 코드를 상의하여 결정한 후
// 각 조건에 맞는 상태코드를 반환해줘야 한다.

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 헤더에서 access키에 담긴 값(토큰)을 꺼낸다.
        String accessToken = request.getHeader("access");

        // 토큰이 없다면 바로 다음 필터로 넘기고 이 필터는 종료한다. (스프링 시큐리티 인증 저장을 하지 않고 종료)
        if (accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰이 있다면 만료 여부를 확인한다. 만료 시 다음 필터로 넘기지 않고 만료되었다고 (인증불가) 응답 후 필터를 종료한다.
        try{
            jwtUtil.isExpired(accessToken);
        } catch (ExpiredJwtException e) {
            // 응답 body
            PrintWriter writer = response.getWriter();
            writer.print("Access Token Expired.");

            // 응답 http 상태코드
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            // 토큰이 있지만 만료된 경우에는 다음 필터로 요청을 넘겨주지 않는다. 그냥 요청을 없앤다.
            return;
        }

        // 토큰이 access인지 확인(발급 시 페이로드에 명시되어있음). access토큰이 아닌 경우(키 이름이 access가 아닌 경우) 인증 불가 응답 후 필터를 종료한다.
        String category = jwtUtil.getCategory(accessToken);
        if (!category.equals("access")) {
            // 응답 body
            PrintWriter writer = response.getWriter();
            writer.print("Invalid Access Token");

            // 응답 http 상태코드
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            // 토큰이 있지만 문제가 있는 경우에도 다음 필터로 요청을 넘겨주지 않는다. 그냥 요청을 없앤다.
            return;
        }

        // 여기까지 통과했다면 토큰이 만료되지도 않았고, access토큰으로 발급된 토큰이 맞으므로
        // 해당 토큰 payload에서 username, role값 가져오기
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        User user = new User();
        user.setUsername(username);
        user.setRole(role);

        // Spring Security Context에 인증정보를 등록하기 위해 CustomUserDetails에 전달.
        CustomUserDetails customUserDetails = new CustomUserDetails(user);

        // 인증정보 저장 (스프링 시큐리티 세션 생성)
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        // 다음 필터로.
        filterChain.doFilter(request, response);
    }
}


