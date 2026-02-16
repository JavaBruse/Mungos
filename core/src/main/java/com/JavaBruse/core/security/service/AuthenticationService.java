package com.JavaBruse.core.security.service;

import com.JavaBruse.core.security.domain.dto.FirstUpdateRequest;
import com.JavaBruse.core.security.domain.dto.JwtAuthenticationResponse;
import com.JavaBruse.core.security.domain.dto.SignInRequest;
import com.JavaBruse.core.security.domain.dto.SignUpRequest;
import com.JavaBruse.core.security.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserService userService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;


    public void addUser(SignUpRequest request) {
        var user = User.builder()
                .username(request.getUsername())
                .fullName(request.getFullname())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .updated(false)
                .build();

        userService.create(user);
    }

    public JwtAuthenticationResponse updatePassword(FirstUpdateRequest request) {

        var user = User.builder()
                .id(UUID.randomUUID().toString())
                .username(request.getUsername())
                .fullName(request.getFullName())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();
        user = userService.update(user);
        var jwt = jwtService.generateToken(user);
        return new JwtAuthenticationResponse(jwt);
    }

    public JwtAuthenticationResponse signIn(SignInRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
        ));

        var user = userService
                .userDetailsService()
                .loadUserByUsername(request.getUsername());

        var jwt = jwtService.generateToken(user);
        return new JwtAuthenticationResponse(jwt);
    }

    public String getUUID(Authentication authentication) {
        return userService.getByUsername(authentication.getName()).getId();
    }
}
