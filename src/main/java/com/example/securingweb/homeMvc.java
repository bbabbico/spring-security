package com.example.securingweb;

import com.example.securingweb.login.MemberUserDetails;
import com.example.securingweb.member.Member;
import com.example.securingweb.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Collection;
import java.util.Iterator;

@RequiredArgsConstructor
@Controller
public class homeMvc {

    private final MemberRepository memberRepository;

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
    @GetMapping("/hello")
    public String hello(@AuthenticationPrincipal MemberUserDetails user ,Model model) { //@AuthenticationPrincipal authentication 를 꺼내와서 객체에 맞게 매핑해줌.
        Member member = memberRepository.findByLoginId(user.getMember().getLoginId()).get();
        model.addAttribute("member", member);
        return "hello";
    }
}
