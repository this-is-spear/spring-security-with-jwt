package tis.springsecurityjwt.domain;

import javax.persistence.*;

@Entity
@Table(name = "authority")
public class Authority {

    @Id
    @Column(name = "authority_name", length = 50)
    private String authorityName;

    public Authority(String authorityName) {
        this.authorityName = authorityName;
    }

    protected Authority() {/*no-op*/}

    public String getAuthorityName() {
        return authorityName;
    }
}
