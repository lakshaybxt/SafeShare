package com.lakshay.safeShare_be.controller;

import com.lakshay.safeShare_be.domain.dto.LoginUserDto;
import com.lakshay.safeShare_be.domain.dto.RegisterUserDto;
import com.lakshay.safeShare_be.domain.dto.VerifyUserDto;
import com.lakshay.safeShare_be.domain.entity.User;
import com.lakshay.safeShare_be.response.LoginResponse;
import com.lakshay.safeShare_be.service.AuthenticationService;
import com.lakshay.safeShare_be.service.JwtService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth")
@Slf4j
@RequiredArgsConstructor
public class AuthenticationController {

    private final JwtService jwtService;
    private final AuthenticationService authenticationService;

    @PostMapping(path = "/signup")
    public ResponseEntity<User> register(@Valid @RequestBody RegisterUserDto registerUserDto) {
        User registeredUser = authenticationService.signUp(registerUserDto);
        log.info(String.valueOf(registeredUser));
        System.out.println(registeredUser);
        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping(path = "/login")
    public ResponseEntity<LoginResponse> authenticate(@Valid @RequestBody LoginUserDto loginUserDto) {
        UserDetails userDetails = authenticationService.authenticate(loginUserDto);
        String jwtToken = jwtService.generateToken(userDetails);
        LoginResponse loginResponse = LoginResponse.builder()
                .token(jwtToken)
                .expiration(jwtService.getExpirationTime())
                .build();

        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping(path = "/verify")
    public ResponseEntity<?> verifyUser(@Valid @RequestBody VerifyUserDto verifyUserDto) {
        try {
            authenticationService.verifyUser(verifyUserDto);
            return ResponseEntity.ok("Account verified successfully");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping(path = "/resend")
    public ResponseEntity<?> resendVerificationCode(@RequestParam String email) {
        try {
            authenticationService.resendVerificationCode(email);
            return ResponseEntity.ok("Verification code sent");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
