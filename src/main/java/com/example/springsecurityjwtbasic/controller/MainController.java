package com.example.springsecurityjwtbasic.controller;

import com.example.springsecurityjwtbasic.config.SecurityConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Collection;
import java.util.Iterator;

@Controller
@ResponseBody   // 웹 페이지(뷰)를 리턴해 줄 것이 아니라 특정 데이터를 리턴할 것이기 때문에 @ResponseBody 어노테이션 작성
public class MainController {

    @GetMapping("/")
    public String mainP() {
        // 생성된 세션을 통해 사용자 아이디, role 등의 사용자 정보를 가져와 추출해서 사용할 수 있다. name(username)과 role을 추출하는 방법은 아래와 같다.
        // 세션 현재 사용자 아이디 가져오기
        String name = SecurityContextHolder.getContext().getAuthentication().getName();

        // 세션 현재 사용자 Role 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        return "Main Controller " + name + " " + role;
    }

}
