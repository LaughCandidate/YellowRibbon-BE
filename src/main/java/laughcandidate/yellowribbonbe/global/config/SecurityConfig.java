package laughcandidate.yellowribbonbe.global.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import laughcandidate.yellowribbonbe.auth.filter.CustomLogoutFilter;
import laughcandidate.yellowribbonbe.auth.filter.CustomUserLoginFilter;
import laughcandidate.yellowribbonbe.auth.filter.JwtAuthenticationFilter;
import laughcandidate.yellowribbonbe.auth.handler.CustomAccessDeniedHandler;
import laughcandidate.yellowribbonbe.auth.handler.CustomAuthenticationEntryPoint;
import laughcandidate.yellowribbonbe.auth.jwt.TokenProvider;
import laughcandidate.yellowribbonbe.user.entity.Role;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private static final String[] WHITELIST = {
		"/swagger-ui/**",
		"/v3/api-docs/**",
		"/swagger-resources/**",
		"/webjars/**",
		"/actuator/**",
		"/auth/login",
		"/auth/check-phone",
		"/auth/send-code",
		"/auth/verify-code",
		"/auth/register"
	};

	private static final String[] BLACKLIST = {
		"/auth/logout"
	};

	private final TokenProvider tokenProvider;
	private final ObjectMapper objectMapper;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager)
		throws Exception {
		http
			.cors(AbstractHttpConfigurer::disable)
			.csrf(AbstractHttpConfigurer::disable)
			.formLogin(AbstractHttpConfigurer::disable)
			.httpBasic(AbstractHttpConfigurer::disable)
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/admin/**").hasAuthority(Role.ROLE_ADMIN.getRole())
				.requestMatchers(WHITELIST).permitAll()
				.requestMatchers(BLACKLIST).authenticated()
				.anyRequest().authenticated())
			.addFilterAt(new CustomUserLoginFilter(authenticationManager, tokenProvider, objectMapper),
				UsernamePasswordAuthenticationFilter.class)
			.addFilterAfter(new JwtAuthenticationFilter(tokenProvider, WHITELIST, BLACKLIST, objectMapper),
				CustomUserLoginFilter.class)
			.addFilterBefore(new CustomLogoutFilter(tokenProvider, objectMapper), LogoutFilter.class)

			.exceptionHandling(exceptions -> exceptions
				.authenticationEntryPoint(new CustomAuthenticationEntryPoint(objectMapper))
				.accessDeniedHandler(new CustomAccessDeniedHandler(objectMapper)));

		return http.build();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}
}