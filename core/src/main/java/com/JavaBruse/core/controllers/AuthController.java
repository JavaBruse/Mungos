package com.javabruse.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import com.javabruse.domain.dto.JwtAuthenticationResponse;
import com.javabruse.domain.dto.SignInRequest;
import com.javabruse.domain.dto.SignUpRequest;
import com.javabruse.service.AuthenticationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationService authenticationService;

    @Operation(summary = "Регистрация пользователя", description = "Создает нового пользователя и возвращает JWT токен")
    @ApiResponse(responseCode = "200", description = "Токен успешно получен",
            content = @Content(schema = @Schema(implementation = JwtAuthenticationResponse.class)))
    @PostMapping("/sign-up")
    public JwtAuthenticationResponse signUp(@RequestBody @Valid SignUpRequest request) {
        return authenticationService.signUp(request);
    }

    @Operation(summary = "Авторизация пользователя")
    @PostMapping("/sign-in")
    public JwtAuthenticationResponse signIn(@RequestBody @Valid SignInRequest request) {
        return authenticationService.signIn(request);
    }

    @Operation(summary = "Проверка токена")
    @GetMapping("/validate")
    public ResponseEntity<String> validateToken(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return ResponseEntity.ok(authenticationService.getUUID(authentication));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
    }
}

