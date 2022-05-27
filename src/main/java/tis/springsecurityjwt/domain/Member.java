package tis.springsecurityjwt.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import tis.springsecurityjwt.domain.Authority;

import javax.persistence.*;
import java.util.Collections;
import java.util.Set;

@Entity
@Table(name = "member")
public class Member {

    @JsonIgnore
    @Id
    @Column(name = "member_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @Column(name = "username", length = 50, unique = true)
    private String username;

    @JsonIgnore
    @Column(name = "password", length = 100)
    private String password;

    @Column(name = "nickname", length = 50)
    private String nickname;

    @JsonIgnore
    @Column(name = "activated")
    private boolean activated;

    @ManyToMany
    @JoinTable(
        name = "user_authority",
        joinColumns = {@JoinColumn(name = "member_id", referencedColumnName = "member_id")},
        inverseJoinColumns = {@JoinColumn(name = "authority_name", referencedColumnName = "authority_name")})
    private Set<Authority> authorities = new java.util.LinkedHashSet<>();

    protected Member() {/*no-op*/}

    public Member(Long userId, String username, String password, String nickname, boolean activated, Set<Authority> authorities) {
        this.userId = userId;
        this.username = username;
        this.password = password;
        this.nickname = nickname;
        this.activated = activated;
        this.authorities = authorities;
    }

    public void setAuthorities(Set<Authority> authorities) {
        this.authorities = authorities;
    }

    public Set<Authority> getAuthorities() {
        return Collections.unmodifiableSet(authorities);
    }

    public Long getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getNickname() {
        return nickname;
    }

    public boolean isActivated() {
        return activated;
    }
}
