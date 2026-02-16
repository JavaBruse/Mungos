package com.JavaBruse.core.security.controllers;

import com.JavaBruse.core.security.domain.dto.JwtAuthenticationResponse;
import com.JavaBruse.core.security.domain.dto.SignUpRequest;
import com.JavaBruse.core.security.domain.dto.UserDTO;
import com.JavaBruse.core.security.domain.model.Role;
import com.JavaBruse.core.security.service.AuthenticationService;
import com.JavaBruse.core.security.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/users-control")
public class UserController {
    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    private final AuthenticationService authenticationService;
    private final UserService userService;

    @PostMapping("/create")
    @ResponseStatus(HttpStatus.CREATED)
    public void signUp(@RequestBody @Valid SignUpRequest request) {
        authenticationService.addUser(request);
    }

    @GetMapping("/roles")
    public List<Role> getRole() {
        return Arrays.stream(Role.values()).toList();
    }

    @GetMapping("/users")
    public List<UserDTO> getUsers() {
        return userService.getAll();
    }

    @DeleteMapping("/delete/{id}")
    public void deleteUser (@PathVariable String id) {
        userService.deleteUser(id);
    }

    @PutMapping("/change-password/{id}")
    public String changePassword(@PathVariable String id) {
        return "Password changed for user: " + id;
    }

    @GetMapping("/blocked/{id}")
    public void getUsers(@PathVariable String id) {

    }
}
