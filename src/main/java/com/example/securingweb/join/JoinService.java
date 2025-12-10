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
        String Username = joinDTO.getUsername();
        log.info( "사용자명 : "+Username+"\n비밀번호 : "+Password);

        data.setName(Username);
        data.setPassword(Password);
        data.setEmail("eeewqd@ddqe");
        data.setLoginId(joinDTO.getUsername());
//        data.setRole("ROLE_USER");


        userRepository.save(data);
    }
}
