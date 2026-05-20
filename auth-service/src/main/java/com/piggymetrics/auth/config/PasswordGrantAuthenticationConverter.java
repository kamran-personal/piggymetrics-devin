package com.piggymetrics.auth.config;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

public class PasswordGrantAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (!"password".equals(grantType)) {
			return null;
		}

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

		String username = request.getParameter("username");
		String password = request.getParameter("password");
		String scope = request.getParameter(OAuth2ParameterNames.SCOPE);

		Set<String> scopes = StringUtils.hasText(scope)
				? new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")))
				: null;

		Map<String, Object> additionalParameters = new HashMap<>();
		request.getParameterMap().forEach((key, values) -> {
			if (!OAuth2ParameterNames.GRANT_TYPE.equals(key)
					&& !OAuth2ParameterNames.SCOPE.equals(key)
					&& !"username".equals(key) && !"password".equals(key)) {
				additionalParameters.put(key, values[0]);
			}
		});

		return new PasswordGrantAuthenticationToken(
				clientPrincipal, username, password, scopes, additionalParameters);
	}
}
