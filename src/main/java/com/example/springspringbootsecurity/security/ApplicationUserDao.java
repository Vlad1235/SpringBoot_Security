package com.example.springspringbootsecurity.security;

import java.util.Optional;

/**
 * Любой класс хранения данных пользователей должен будет реализовать данных интерфейс.
 * Через использование интерфейса достигается широта возможных вариантом хранения данных пользователей.
 */
public interface ApplicationUserDao {
    Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
