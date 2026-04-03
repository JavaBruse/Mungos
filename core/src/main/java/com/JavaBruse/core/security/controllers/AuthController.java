package com.JavaBruse.core.security.controllers;

import com.JavaBruse.core.security.domain.model.AuditAction;
import com.JavaBruse.core.security.domain.DTO.FirstUpdateRequest;
import com.JavaBruse.core.security.domain.DTO.JwtAuthenticationResponse;
import com.JavaBruse.core.security.domain.DTO.SignInRequest;
import com.JavaBruse.core.security.service.AuthenticationService;
import com.JavaBruse.core.security.service.AuditLogService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authenticationService;
    private final AuditLogService auditLogService;

    @PostMapping("/update-in")
    public JwtAuthenticationResponse update(@RequestBody @Valid FirstUpdateRequest request) {
        auditLogService.log(AuditAction.UPDATE_USER_ROLE);
        return authenticationService.updatePassword(request);
    }

    @PostMapping("/sign-in")
    public JwtAuthenticationResponse signIn(@RequestBody @Valid SignInRequest request) {
        return authenticationService.signIn(request);
    }
}

