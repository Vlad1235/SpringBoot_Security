package com.example.springspringbootsecurity.security.dbChosenRealization;


import com.example.springspringbootsecurity.security.ApplicationUser;
import com.example.springspringbootsecurity.security.ApplicationUserDao;
import com.google.common.collect.Lists; // GUAVA library usage
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.springspringbootsecurity.security.ApplicationRoles.*;


/**
 * Для упрощения кода также используем in-memory базу данных
 * В реальном проекте данный класс будет дергать информацию из базы данных.
 */
@Repository("simpleLogic")
public class DbConnectionRealisation implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public DbConnectionRealisation(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getAllAuthenticatedClientsStoredInDB()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    /*
    Для простоты hardcode пользователей.
    В реальном проекте, они будут хранится в базе данных
     */
    private List<ApplicationUser> getAllAuthenticatedClientsStoredInDB() {
        List<ApplicationUser> clients = Lists.newArrayList(
                new ApplicationUser(
                        "anna",
                        passwordEncoder.encode("1234"),
                        STUDENT.grantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "linda",
                        passwordEncoder.encode("1234"),
                        ADMIN.grantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "tom",
                        passwordEncoder.encode("1234"),
                        ADMINTRAINEE.grantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );
        return clients;
    }
}
