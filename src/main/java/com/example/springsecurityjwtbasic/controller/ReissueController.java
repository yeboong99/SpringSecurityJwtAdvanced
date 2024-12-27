package com.example.springsecurityjwtbasic.controller;

import com.example.springsecurityjwtbasic.domain.Refresh;
import com.example.springsecurityjwtbasic.jwt.JWTUtil;
import com.example.springsecurityjwtbasic.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;

@Controller
@ResponseBody // 이제 안 사실 : @Controller + @ResponseBody => @RestController였다..
@RequiredArgsConstructor
public class ReissueController {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    // reissue(프론트에서 access토큰을 재발급해달라는 요청을 했을 때)시 로직 작성.
    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        // refresh 토큰 가져오기 (쿠키로부터 순수 token을 꺼내온다)
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if(cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }

        // 쿠키에 리프레시 토큰이 없는 경우
        if(refresh == null) {
            // 응답 상태 코드
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        // 꺼낸 토큰이 만료된 경우
        try{
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {
            // 응답 상태 코드
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        // 토큰이 refresh토큰이 맞는지 확인 (발급 시 페이로드에 명시되어있음)
        String category = jwtUtil.getCategory(refresh);
        if (!category.equals("refresh")) {
            // 응답 상태 코드
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        // 여기까지 왔으면 쿠키에서 유효한 리프레시 토큰이 꺼내진 것.

        // DB에 refresh 토큰이 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {
            // 응답 상태 코드
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }
        // 유저 정보 꺼내오기.
        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        // 새 access 토큰 발급
        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);
        // 새 refresh 토큰 발급
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        // refresh 토큰 저장 db에 기존 refresh토큰 삭제 후 새 refresh토큰 저장
        refreshRepository.deleteByRefresh(refresh);
        addRefreshEntity(username, newRefresh, 86400000L);

        // 응답 헤더에 새로운 access토큰 넣어주기
        response.setHeader("access", newAccess);
        response.addCookie(createCookie("refresh", newRefresh));

        return new ResponseEntity<>(HttpStatus.OK); // 200 상태코드와 함께 전송
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
//        cookie.setSecure(true);
//        cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }

    // 새 refresh토큰 db에 저장해주는 메서드
    private void addRefreshEntity(String username, String refresh, Long expiredMs) {
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        Refresh refreshEntity = new Refresh();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }
}
