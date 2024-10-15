package com.security.NewApp.service;

import com.security.NewApp.model.User;

public interface UserService {
    User registerUser(User user);
    User findByUsername(String username);
    User findByEmail(String email);


}
