package com.fa.backend;

import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class SecurityController {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;
    private JwtCore jwtCore;

    @Autowired
    public void setUserRepository(UserRepository userRepository){
        this.userRepository = userRepository;
    }
    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder){
        this.passwordEncoder = passwordEncoder;
    }
    @Autowired
    public void setAuthenticationManager(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }

    @Autowired
    public void setJwtCore(JwtCore jwtCore){
        this.jwtCore = jwtCore;
    }

    @PostMapping("/signup")
    ResponseEntity<?> signup(@RequestBody SignupRequest signupRequest){
        if (userRepository.existsUserByUsername(signupRequest.getUsername())){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Choose different name");
        }

        String hashed = passwordEncoder.encode(signupRequest.getPassword());
        User user = new User();
        user.setUsername(signupRequest.getUsername());
        user.setPassword(hashed);
        userRepository.save(user);
        return ResponseEntity.ok("Success");
    }
    @PostMapping("/signin")
    ResponseEntity<?> signin(@RequestBody SigninRequest signinRequest){
        Authentication authentication = null;
        try {

            UsernamePasswordAuthenticationToken token =  new UsernamePasswordAuthenticationToken(
                    signinRequest.getUsername(),
                    signinRequest.getPassword());
            authentication = authenticationManager.authenticate(token);

        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtCore.generateToken(authentication);
        return ResponseEntity.ok(jwt);
    }

    }

