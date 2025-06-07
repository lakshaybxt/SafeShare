package com.lakshay.safeShare_be.service;

import org.springframework.security.core.userdetails.UserDetails;

public interface JwtService {
    String generateToken(UserDetails userDetails);
    String extractUsername(String token);
    boolean validateToken(String token, UserDetails userDetails);
    long getExpirationTime();
}
