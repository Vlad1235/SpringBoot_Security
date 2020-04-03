package com.example.springspringbootsecurity.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

/**
 * Наследуем класс UsernamePasswordAuthenticationFilter, чтобы
 * переопределить дефолтную реализацию Spring Security валидации credentials полученных от пользователя
 */
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /*
    Метод который
    1. вытащит из запроса логин и пароль
    2. создаст класс в который их положит(мы изначально создали шаблон)
    3. произведет аутентификацию данных
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest =
                    new ObjectMapper().readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class); //мапаем данные в подготовленный класс
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );
            Authentication authenticate = authenticationManager.authenticate(authentication); // here authentication manager will make sure user is exits (validate)
        return authenticate;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /*
    Данный метод будет работать, только если метод attemptAuthentication успешно завершился
    Данный метод
    1.создаст token
    2.отправит обратно клиенту
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        String key = "secureSecureSecureSecureSecureSecure"; // как можно длиннее и сложнее
        String token = Jwts.builder()
                                .setSubject(authResult.getName())
                                .claim("authorities", authResult.getAuthorities())
                                .setIssuedAt(new Date())
                                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2))) // expiration time for jwt
                                .signWith(Keys.hmacShaKeyFor(key.getBytes()))
                                .compact();

       response.addHeader("Authorization","Bearer " + token); // send token back to client
    }
}
