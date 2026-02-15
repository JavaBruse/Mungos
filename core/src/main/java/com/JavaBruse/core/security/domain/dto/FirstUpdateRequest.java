package com.JavaBruse.core.security.domain.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class FirstUpdateRequest {
    @Size(min = 5, max = 50, message = "Имя пользователя должно содержать от 5 до 50 символов")
    @NotBlank(message = "Имя пользователя не может быть пустыми")
    private String username;

    @Size(min = 5, max = 255, message = "Полное имя пользователя от 5 до 255 символов")
    @NotBlank(message = "Полное имя не может быть пустыми")
    private String fullName;

    @Size(max = 255, message = "Длина пароля должна быть не более 255 символов")
    private String password;
}
