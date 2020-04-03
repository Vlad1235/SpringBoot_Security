package com.example.springspringbootsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.springspringbootsecurity.security.ApplicationRoles.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // подлючение использования аннотаций для установления ролей и разрешений
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public SecurityConfig(PasswordEncoder passwordEncoder,
                          ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    /*
    Порядок следования antMatcher важен
    Закомментированы, так как заменили аннотациями на самих контроллерах
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name()) // from this API and deeper only users with Role STUDENT can access
                .anyRequest()
                .authenticated()
                .and()
                .formLogin() // Более не используется стандартная форма браузера. Теперь будет создаваться SESSIONID и клиента при каждом зарпосе в Cookies отправяемых серверу будет вкладывать его. Не нужно будет проходить аутентификацию.
                            .loginPage("/login").permitAll() // подключаем свою страницу с кастомизированной формой и выносим ее из под Spring Security
                            .defaultSuccessUrl("/courses",true) // по умолчанию, после успешной аутентификации клиент перенаправляется на index.html. Мы указываем куда хотим чтобы перенаправлялся он.
                            .passwordParameter("coolpassword") // сам назвал
                            .usernameParameter("coolusername") // сам назвал
                .and()
                .rememberMe()
                            .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(2)) // хранить 2 суток. Хранение будет в im-memory базе данных. Не для настоящего проекта.
                            .key("somethingVerySecured")
                            .rememberMeParameter("longer-remember-me") // сам назвал
                .and()
                .logout() // кастомизируем выход из приложения
                            .logoutUrl("/logout")
                            .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET")) // если .csrf().disable() мы должны вставить данную строку. Это плохая практика. В проекте, вспользовать csrf()
                            .clearAuthentication(true)
                            .invalidateHttpSession(true)
                            .deleteCookies("JSESSIONID","remember-me")
                            .logoutSuccessUrl("/login");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
