package ra.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;
import ra.security.model.domain.Users;
import ra.security.model.dto.request.FormSignInDto;
import ra.security.model.dto.request.FormSignUpDto;
import ra.security.model.dto.response.JwtResponse;
import ra.security.security.jwt.JwtProvider;
import ra.security.security.user_principle.UserPrinCiple;
import ra.security.service.IUserService;
import ra.security.service.iml.UserService;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v4/auth")
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private IUserService userService;

    @GetMapping
    public ResponseEntity<String> Home() {
        return ResponseEntity.ok("Nice");
    }

    @PostMapping("/sign-in")
    public ResponseEntity<JwtResponse> signIn(@RequestBody FormSignInDto formSignInDto) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            formSignInDto.getUsername(),
                            formSignInDto.getPassword()));
            //tao doi tuong authentication de xac thuc thong qua username va password
            // tao token va tra ve cho nguoi dung
            String token = jwtProvider.generateToken(authentication);
            // lay ra user principle
            UserPrinCiple userPrinCiple = (UserPrinCiple) authentication.getPrincipal();
            List<String> roles = userPrinCiple.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority).collect(Collectors.toList());
            return ResponseEntity.ok(JwtResponse.builder()
                    .token(token)
                    .name(userPrinCiple.getName())
                    .username(userPrinCiple.getUsername())
                    .roles(roles)
                    .status(userPrinCiple.getStatus()).build());
        } catch (AuthenticationException e) {
            throw new RuntimeException(e);
        }
    }

    @PostMapping("/sign-up")
    public ResponseEntity<String> signUp(@RequestBody FormSignUpDto formSignUpDto) {
        Users users = userService.save(formSignUpDto);
        return new ResponseEntity(users, HttpStatus.CREATED);
    }
}
