package com.example.springspringbootsecurity;

import com.example.springspringbootsecurity.jwt.JwtConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(JwtConfig.class)
public class SpringSpringbootSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSpringbootSecurityApplication.class, args);
	}

}
