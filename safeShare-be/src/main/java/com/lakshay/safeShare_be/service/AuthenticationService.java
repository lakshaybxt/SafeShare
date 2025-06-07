package com.lakshay.safeShare_be.service;

import com.lakshay.safeShare_be.domain.dto.LoginUserDto;
import com.lakshay.safeShare_be.domain.dto.RegisterUserDto;
import com.lakshay.safeShare_be.domain.dto.VerifyUserDto;
import com.lakshay.safeShare_be.domain.entity.User;
import org.springframework.security.core.userdetails.UserDetails;

public interface AuthenticationService {
    User signUp(RegisterUserDto request);
    UserDetails userDetails(LoginUserDto request);
    void verifyUser(VerifyUserDto request);
    void sendVerificationCode(String email);
}
