package com.JavaBruse.core.security.domain.dto;

import com.JavaBruse.core.security.domain.model.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {
    private String id;
    private String username;
    private String fullName;
    private Role role;
    private Boolean updated = false;
}
