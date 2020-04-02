package com.example.springspringbootsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.springspringbootsecurity.security.ApplicationPermissions.*;
import static com.example.springspringbootsecurity.security.ApplicationRoles.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public SecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    /*
    Порядок следования antMatchers важен. Не забывать.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name()) // from this API and deeper only users with Role STUDENT can access
                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission()) // на основе разрешений(permissions), а не ролей(roles). Доступ имеет лишь тот, у кого есть разрашение писать.
                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())// все остальное, для обоих возможно. Тут ограничение по роли.
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
//                                        .roles(STUDENT.name()) // авторизация на основе роли
                                        .authorities(STUDENT.grantedAuthorities()) // авторизация на основе разрешений(permissions)
                                        .build();

            UserDetails lindaUser = User.builder()
                                        .username("linda")
                                        .password(passwordEncoder.encode("password1234"))
//                                        .roles(ADMIN.name()) // авторизация на основе роли
                                        .authorities(ADMIN.grantedAuthorities()) // авторизация на основе разрешений(permissions)
                                        .build();

            UserDetails tomUser = User.builder()
                                        .username("tom")
                                        .password(passwordEncoder.encode("1234"))
//                                        .roles(ADMINTRAINEE.name()) // авторизация на основе роли
                                        .authorities(ADMINTRAINEE.grantedAuthorities()) // авторизация на основе разрешений(permissions)
                                        .build();

        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser,
                tomUser
        );
    }
}
