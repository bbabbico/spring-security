package com.example.securingweb;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Collection;
import java.util.Iterator;

@Controller
public class homeMvc {
    @GetMapping("/")
    public String index() {
        return "home";
    }
    @GetMapping("/home")
    public String home(Model model) {
        
        //세션 정보
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String name = authentication.getName(); //Member 의 name 이 아니라 시큐리티에 저장된 name임

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iter = authorities.iterator();
        GrantedAuthority auth = iter.next();
        String role = auth.getAuthority();


        model.addAttribute("name", name);
        model.addAttribute("role", role);
        return "home";
    }
}
