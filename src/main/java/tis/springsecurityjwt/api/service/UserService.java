package tis.springsecurityjwt.api.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tis.springsecurityjwt.api.dto.MemberDto;
import tis.springsecurityjwt.config.security.SecurityUtil;
import tis.springsecurityjwt.domain.Authority;
import tis.springsecurityjwt.domain.Member;
import tis.springsecurityjwt.domain.MemberRepository;

import java.util.Collections;
import java.util.Optional;

@Service
public class UserService {
    private final MemberRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(MemberRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public Member signup(MemberDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        Authority authority = new Authority("ROLE_USER");

        Member user = new Member(null, userDto.getUsername(), passwordEncoder.encode(userDto.getPassword()),
            userDto.getNickname(), true, Collections.singleton(authority));

        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public Optional<Member> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<Member> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}
