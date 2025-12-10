package com.example.securingweb.member;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 회원정보 클래스
 * <p>
 * DAO 인터페이스 : {@link MemberRepository}
 */
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; //사용자 식별 번호

    @Column(length = 100 , nullable = false)
    private String email;    //이메일

    @Column(length = 30 , nullable = false)
    private String loginId;  //로그인 ID

    @Column(length = 20 , nullable = false)
    private String name;     //사용자 이름

    @Column(length = 61 , nullable = false) // BCryptPasswordEncoder
    private String password; //비밀번호

    @Override
    public String toString() {
        return "Member{" +
                "id=" + id +
                ", email='" + email + '\'' +
                ", loginId='" + loginId + '\'' +
                ", name='" + name + '\'' +
                ", password='" + password + '\'' +
                '}';
    }
}