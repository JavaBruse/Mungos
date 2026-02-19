package com.JavaBruse.core.security.converters;

import com.JavaBruse.core.security.domain.DTO.UserDTO;
import com.JavaBruse.core.security.domain.model.User;
import org.springframework.stereotype.Component;

@Component
public class UserConverter {
    public static UserDTO userToUserDTO(User user) {
        UserDTO userDTO = new UserDTO();
        userDTO.setId(user.getId());
        userDTO.setUsername(user.getUsername());
        userDTO.setFullName(user.getFullName());
        userDTO.setUpdated(user.getUpdated());
        userDTO.setRole(user.getRole());
        return userDTO;
    }
}
