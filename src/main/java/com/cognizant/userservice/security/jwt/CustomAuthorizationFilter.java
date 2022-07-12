package com.cognizant.userservice.security.jwt;

import static java.util.Arrays.stream;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

//		if it is a login path then we don't want to do anything
		if (request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")) {
			filterChain.doFilter(request, response);
		} else {
			// here we read token from Authorization Header
			final String authorizationHeader = request.getHeader("Authorization");

			// from here we fetch username form jwt token
			if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
				try {
					String token = authorizationHeader.substring("Bearer ".length());
					Algorithm algorithm = Algorithm.HMAC512("secret".getBytes());

					JWTVerifier verifier = JWT.require(algorithm).build();
					DecodedJWT decodedJWT = verifier.verify(token);

					String username = decodedJWT.getSubject();
					String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
					Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
					stream(roles).forEach(role -> {
						authorities.add(new SimpleGrantedAuthority(role));
					});
					UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
							username, null, authorities);
					SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
					filterChain.doFilter(request, response);
				} catch (Exception e) {
					log.error("Error loggig in : {}", e.getMessage());
					response.setHeader("error", e.getMessage());
//					response.sendError(403, "Forbbidden");

					Map<String, String> error = new HashMap<>();
					error.put("error_message", e.getMessage());

					response.setContentType("application/json");
					new ObjectMapper().writeValue(response.getOutputStream(), error);

				}

			} else {
				filterChain.doFilter(request, response);
			}
		}

	}

}
