package com.example.securingweb.login;

import com.example.securingweb.member.Member;
import com.example.securingweb.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberUserDetailsService implements UserDetailsService { //시큐리티 로그인 과정에서 UserDetailsService 를 정의.

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String LoginId) throws UsernameNotFoundException {
        Member member = memberRepository.findByLoginId(LoginId).get();
        return new MemberUserDetails(member);
    }
}
