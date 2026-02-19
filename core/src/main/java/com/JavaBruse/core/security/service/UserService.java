package com.JavaBruse.core.security.service;

import com.JavaBruse.core.security.converters.UserConverter;
import com.JavaBruse.core.security.domain.DTO.UserDTO;
import com.JavaBruse.core.security.domain.model.Role;
import com.JavaBruse.core.security.domain.model.User;
import com.JavaBruse.core.exaption.ExistsExeption;
import com.JavaBruse.core.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository repository;

    public User save(User user) {
        return repository.save(user);
    }

    public User create(User user) {
        if (repository.existsByUsername(user.getUsername())) {
            throw new ExistsExeption("Пользователь с \"" + user.getUsername() + "\" таким именем уже существует");
        }
        return save(user);
    }

    public List<UserDTO> getAll() {
        return repository.findAll().stream().map(UserConverter::userToUserDTO).toList();
    }

    public void deleteUser(String id){
        if (!repository.existsById(id)) {
            throw new ExistsExeption("Пользователь с \"" + id + "\" не существует");
        }
        repository.deleteById(id);
    }

    public User update(User user) {
        User userDB = repository.findByUsername(user.getUsername()).orElseThrow();
        if (!userDB.getUpdated()) {
            userDB.setUpdated(true);
            userDB.setFullName(user.getFullName());
            userDB.setPassword(user.getPassword());
        }
        return save(userDB);
    }

    public User getByUsername(String username) {
        return repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден"));

    }

    public UserDetailsService userDetailsService() {
        return this::getByUsername;
    }

    public User getCurrentUser() {
        // Получение имени пользователя из контекста Spring Security
        var username = SecurityContextHolder.getContext().getAuthentication().getName();
        return getByUsername(username);
    }


    @Deprecated
    public void getAdmin() {
        var user = getCurrentUser();
        user.setRole(Role.ROLE_ADMIN);
        save(user);
    }
}
