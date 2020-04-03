package com.example.springspringbootsecurity.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Фильтр(класс) который будет
 * 1. пропускать через себя запросы клиентов(request)
 * 2. искать в заголовках вопросов токены
 * 3. проверять их валидность
 * 4. передавать следующему по цепочку фильтру(в нашем случае других нет больше и следовательно будет доступ к API)

 * OncePerRequestFilter означает фильтр будет запускаться на каждый запрос, НО лишь 1 раз.
 * Есть фильтры которые могу запускать несколько раз на 1 запрос.
 * Важно помнить, что все фильтры нужно связывать по цепочке между собой.
 */
public class JwtRecievingTokenVerifier extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader("Authorization");
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) { // если в запросе нет jwt или вообще нет заголовка или он пуст
            filterChain.doFilter(request, response);
            return; // отказ
        }
        String token = authorizationHeader.replace("Bearer ",""); // очищаем от заголовка Bearer сам token
        try{
            String secretkey = "secureSecureSecureSecureSecureSecure";
            Jws<Claims> claimsJws = Jwts.parser()
                                            .setSigningKey(Keys.hmacShaKeyFor(secretkey.getBytes()))
                                            .parseClaimsJws(token);
            Claims body = claimsJws.getBody(); // payload вытаскиваем для работы с ним
            String username = body.getSubject(); // вытаскиваем логин
            var authorities = ( List<Map<String,String>> ) body.get("authorities");

            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                                        .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                                        .collect(Collectors.toSet());
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities
            );
            SecurityContextHolder.getContext().setAuthentication(authentication); // authenticate token
        } catch (JwtException e){
            throw new IllegalStateException(String.format("Token %s cannot be trusted",token));
        }
        /*
        Результат данного фильтра надо передать следующему и так по цепочке до послденго перед API.
         */
        filterChain.doFilter(request,response); // принцип цепочки фильтров.
    }
}
