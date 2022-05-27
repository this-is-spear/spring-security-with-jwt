package tis.springsecurityjwt.api.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import tis.springsecurityjwt.api.dto.MemberDto;
import tis.springsecurityjwt.api.service.UserService;
import tis.springsecurityjwt.domain.Member;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<Member> signup(
        @Valid @RequestBody MemberDto userDto
    ) {
        return ResponseEntity.ok(userService.signup(userDto));
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<Member> getMyUserInfo() {
        return ResponseEntity.ok(userService.getMyUserWithAuthorities().get());
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<Member> getUserInfo(@PathVariable String username) {
        return ResponseEntity.ok(userService.getUserWithAuthorities(username).get());
    }
}
