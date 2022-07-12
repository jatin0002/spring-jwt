package com.cognizant.userservice.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.cognizant.userservice.security.jwt.CustomAuthenticationFilter;
import com.cognizant.userservice.security.jwt.CustomAuthorizationFilter;
import com.cognizant.userservice.security.jwt.JwtAuthenticationEntryPoint;

import lombok.RequiredArgsConstructor;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final JwtAuthenticationEntryPoint unauthorizedHandler;
	private final AuthenticationConfiguration authenticationConfiguration;

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		CustomAuthenticationFilter authenticationFilter = new CustomAuthenticationFilter(
				authenticationManagerBean(authenticationConfiguration));
		authenticationFilter.setFilterProcessesUrl("/api/login");

		http.csrf().disable();
		http.authorizeHttpRequests().antMatchers("/api/login/**", "/api/token/refresh/**").permitAll();
		http.authorizeHttpRequests().anyRequest().authenticated();
		http.exceptionHandling().authenticationEntryPoint(unauthorizedHandler);
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		// Here custom AUTHENTICATION filter run
		http.addFilter(authenticationFilter);

		// Verifiv user for 2nd request onwards
		http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}
}
