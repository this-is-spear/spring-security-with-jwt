package tis.springsecurityjwt.config.Jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {
    private static final String ISSUER = "auth0";
    private final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    private final long tokenValidityInMilliseconds;
    private final String authorizationHeader;
    private final Algorithm algorithm;
    private final JWTVerifier verifier;

    public JwtTokenProvider(
        @Value("${jwt.secret}") String secret,
        @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds,
        @Value("${jwt.header}") String authorizationHeader) {
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
        this.authorizationHeader = authorizationHeader;
        this.algorithm = Algorithm.HMAC256(secret);
        this.verifier = JWT.require(algorithm)
            .withIssuer(ISSUER)
            .build();
    }

    public String getAuthoritiesHeaderName() {
        return authorizationHeader;
    }

    public String createToken(Authentication authentication) {
        String authorities = getAuthorities(authentication);
        try {
            long now = (new Date()).getTime();
            Date validity = new Date(now + this.tokenValidityInMilliseconds);

            return JWT.create()
                .withSubject(authentication.getName())
                .withClaim(authorizationHeader, authorities)
                .withIssuer(ISSUER)
                .withExpiresAt(validity)
                .sign(algorithm);

        } catch (JWTCreationException exception) {
            logger.info("Invalid Signing configuration / Couldn't convert Claims.");
            throw new RuntimeException();
        }
    }

    public Authentication getAuthentication(String token) {
        DecodedJWT jwt = verifier.verify(token);
        Collection<? extends GrantedAuthority> authorities = jwt.getClaims()
            .entrySet().stream()
            .map(
                stringClaimEntry -> new SimpleGrantedAuthority(stringClaimEntry.toString())
            ).collect(Collectors.toList());

        User principal = new User(jwt.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public boolean verifyToken(String token) {
        try {
            verifier.verify(token);
            return true;
        } catch (JWTVerificationException exception) {
            logger.info("Invalid signature/claims");
            return false;
        }
    }

    private String getAuthorities(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(","));
        return authorities;
    }
}
