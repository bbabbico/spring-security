package com.example.securingweb.join;

import com.example.securingweb.member.Member;
import com.example.securingweb.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class JoinService {

    private final MemberRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    public void joinProcess(JoinDTO joinDTO) {


        //db에 이미 동일한 username을 가진 회원이 존재하는지?


        Member data = new Member();

        String Password = passwordEncoder.encode(joinDTO.getPassword());
        String Name = joinDTO.getName();
        String LoginId = joinDTO.getLoginId();
        log.info( "\nID : "+LoginId+"\n사용자명 : "+Name+"\n비밀번호 : "+Password +"\n회원가입됨");

        data.setName(Name);
        data.setPassword(Password);
        data.setEmail(joinDTO.getEmail());
        data.setLoginId(LoginId);
        data.setRole("USER"); //그외 계정은 DB에서 직접 주입


        userRepository.save(data);
    }
}
