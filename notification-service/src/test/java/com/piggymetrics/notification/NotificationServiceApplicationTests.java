package com.piggymetrics.notification;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.time.Instant;
import java.util.Map;

@SpringBootTest
public class NotificationServiceApplicationTests {

	@TestConfiguration
	static class TestSecurityConfig {
		@Bean
		public JwtDecoder jwtDecoder() {
			return token -> Jwt.withTokenValue(token)
					.header("alg", "none")
					.claim("sub", "test")
					.issuedAt(Instant.now())
					.expiresAt(Instant.now().plusSeconds(3600))
					.build();
		}
	}

	@Test
	public void contextLoads() {
	}

}
