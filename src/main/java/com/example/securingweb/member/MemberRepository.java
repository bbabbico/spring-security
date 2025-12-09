package com.example.securingweb.member;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * 회원정보({@link Member}) DAO 인터페이스
 */
@Repository
public interface MemberRepository extends JpaRepository<Member,Long> {
    Optional<Member> findByLoginId(String id);
    Optional<Member> findByEmail(String email);
    Optional<Member> findByUsername(String username);
    
    // 중복 확인 메서드
    boolean existsByEmail(String email);
    boolean existsByLoginId(String loginId);
}
