package com.JavaBruse.core.security.controllers;

import com.JavaBruse.core.security.domain.dto.FirstUpdateRequest;
import com.JavaBruse.core.security.domain.dto.JwtAuthenticationResponse;
import com.JavaBruse.core.security.domain.dto.SignInRequest;
import com.JavaBruse.core.security.domain.dto.SignUpRequest;
import com.JavaBruse.core.security.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/security/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authenticationService;

    @PostMapping("/sign-up")
    @ResponseStatus(HttpStatus.CREATED)
    public JwtAuthenticationResponse signUp(@RequestBody @Valid SignUpRequest request) {
        return authenticationService.addUser(request);
    }


    @PostMapping("/update-in")
    public JwtAuthenticationResponse update(@RequestBody @Valid FirstUpdateRequest request) {
        return authenticationService.updatePassword(request);
    }

    @PostMapping("/sign-in")
    public JwtAuthenticationResponse signIn(@RequestBody @Valid SignInRequest request) {
        return authenticationService.signIn(request);
    }

}

