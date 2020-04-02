package com.example.springspringbootsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.springspringbootsecurity.security.ApplicationRoles.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public SecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name()) // from this API and deeper only users with Role STUDENT can access
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();

    }

    /*
    Данный метод позволяет, создать hardcoded пользователей и как одна из возможных реализаций интерфейса UserDetailsService
    вытаскивать данные из in-memory базы данных для сравнения с приходящим запросом на аутентификацию.
    Создаем список пользователей. Которые будут хранится в in-memory базе данных.
     */
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser =  User.builder()
                                        .username("annasmith")
                                        .password(passwordEncoder.encode("password"))
                                        .roles(STUDENT.name())
                                        .build();

            UserDetails lindaUser = User.builder()
                                        .username("linda")
                                        .password(passwordEncoder.encode("password1234"))
                                        .roles(ADMIN.name())
                                        .build();
        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser
        );
    }
}
