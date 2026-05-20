package com.piggymetrics.auth.config;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	static final AuthorizationGrantType PASSWORD_GRANT_TYPE = new AuthorizationGrantType("password");

	private final String username;
	private final String password;
	private final Set<String> scopes;

	public PasswordGrantAuthenticationToken(Authentication clientPrincipal,
			String username, String password, @Nullable Set<String> scopes,
			@Nullable Map<String, Object> additionalParameters) {
		super(PASSWORD_GRANT_TYPE, clientPrincipal, additionalParameters);
		this.username = username;
		this.password = password;
		this.scopes = scopes != null ? scopes : Collections.emptySet();
	}

	public String getUsername() {
		return username;
	}

	@Override
	public Object getCredentials() {
		return password;
	}

	public Set<String> getScopes() {
		return scopes;
	}
}
