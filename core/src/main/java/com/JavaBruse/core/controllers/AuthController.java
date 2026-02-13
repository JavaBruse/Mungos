package com.JavaBruse.core.controllers;

import com.JavaBruse.core.domain.dto.JwtAuthenticationResponse;
import com.JavaBruse.core.domain.dto.SignInRequest;
import com.JavaBruse.core.domain.dto.SignUpRequest;
import com.JavaBruse.core.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authenticationService;

    @PostMapping("/sign-up")
    public JwtAuthenticationResponse signUp(@RequestBody @Valid SignUpRequest request) {
        return authenticationService.addUser(request);
    }


    @PostMapping("/update")
    public JwtAuthenticationResponse update(@RequestBody @Valid SignUpRequest request) {
        return authenticationService.updatePassword(request);
    }

    @PostMapping("/sign-in")
    public JwtAuthenticationResponse signIn(@RequestBody @Valid SignInRequest request) {
        return authenticationService.signIn(request);
    }

}

