package com.example.springspringbootsecurity.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
/*        *//*
        Отключение стандартной аутентификации Spring Security.
        Подключение аутентификации браузера. Отсутствует возможность logout как в Spring Security
         *//*
        http    .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();*/

        /*
        Освобождение от Spring Security указанных API.
        Использование формы браузера
        Для всех API кроме указанных аутентификация требуется
         */
        http
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/js/*")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();

    }
}
