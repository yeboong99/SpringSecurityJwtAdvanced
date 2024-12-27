package com.example.springsecurityjwtbasic.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;


// JWT를 발급하고 검증할 클래스. @Component 어노테이션을 통해 실행과 동시에 스프링 컴포넌트로 등록해야 한다.
@Component
public class JWTUtil {

    private SecretKey secretKey;

    // 암호화 키를 불러와줄 생성자. 암호화 알고리즘으로 어떤것을 사용하는지도 여기서 설정하면 됨.
    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // username을 검증할 메서드
    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
        // 문자열에서 헤더 부분을 뜯어 우리가 가진 secretKey와 맞는지(우리 서버에서 생성한 토큰이 맞는지) 검증, 빌더 타입으로 반환한 뒤 클래임을 확인하여 페이로드 부분에 접근. 그곳에서 username을 찾아 String타입으로 반환.
        // * payload 내 담긴 정보들을 claim이라 한다.
    }

    // role을 검증할 메서드
    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    // 토큰이 만료되었는지 검증할 메서드
    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
        // getExpiration()으로 반환된 시각이 현재 시각 이전이면 true를 반환한다. (만료되었다는 의미.)
    }

    // 토큰을 생성해줄 메서드
    // username과 role, 토큰이 살아있을 시간(ms)을 인자로 받고 jwt builder를 통해 토큰을 만들어 반환.
    public String createJwt(String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("username", username) // payload에 넣을 정보 username
                .claim("role", role)         // payload에 넣을 정보 role
                .issuedAt(new Date(System.currentTimeMillis())) // 토큰이 발행된 날짜 넣어주기(현재시각)
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // 현재 시각으로부터 expiredMs만큼 더한 시각을 만료시각으로 넣어준다.
                .signWith(secretKey)            // secretKey를 통해 암호화를 진행
                .compact(); // Jwt building 마무리(String)
    }


}
