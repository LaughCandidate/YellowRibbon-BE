package laughcandidate.yellowribbonbe.auth.filter;

import org.springframework.security.authentication.AuthenticationManager;

import com.fasterxml.jackson.databind.ObjectMapper;

import laughcandidate.yellowribbonbe.auth.jwt.TokenProvider;

public class CustomUserLoginFilter extends CustomUsernamePasswordAuthenticationFilter {

	private static final String LONGIN_URI = "/auth/login";

	public CustomUserLoginFilter(AuthenticationManager authenticationManager,
		TokenProvider tokenProvider,
		ObjectMapper objectMapper) {
		super(authenticationManager, tokenProvider, objectMapper);
		this.setFilterProcessesUrl(LONGIN_URI);
	}
}
