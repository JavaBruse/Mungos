package com.JavaBruse.core.security.controllers;

import com.JavaBruse.core.security.domain.dto.FirstUpdateRequest;
import com.JavaBruse.core.security.domain.dto.JwtAuthenticationResponse;
import com.JavaBruse.core.security.domain.dto.SignInRequest;
import com.JavaBruse.core.security.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authenticationService;

    @PostMapping("/update-in")
    public JwtAuthenticationResponse update(@RequestBody @Valid FirstUpdateRequest request) {
        return authenticationService.updatePassword(request);
    }

    @PostMapping("/sign-in")
    public JwtAuthenticationResponse signIn(@RequestBody @Valid SignInRequest request) {
        return authenticationService.signIn(request);
    }

}

