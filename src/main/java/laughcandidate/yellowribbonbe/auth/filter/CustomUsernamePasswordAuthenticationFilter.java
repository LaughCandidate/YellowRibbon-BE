package laughcandidate.yellowribbonbe.auth.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StreamUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import laughcandidate.yellowribbonbe.auth.dto.request.LoginRequest;
import laughcandidate.yellowribbonbe.auth.dto.response.LoginResponse;
import laughcandidate.yellowribbonbe.auth.jwt.TokenProvider;
import laughcandidate.yellowribbonbe.auth.jwt.dto.UserTokenResponse;
import laughcandidate.yellowribbonbe.auth.service.CustomUserDetails;
import laughcandidate.yellowribbonbe.auth.util.ResponseUtil;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AuthErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.CommonErrorCode;
import laughcandidate.yellowribbonbe.user.entity.Role;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class CustomUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;
	private final TokenProvider tokenProvider;
	private final ObjectMapper objectMapper;

	public CustomUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager,
		TokenProvider tokenProvider, ObjectMapper objectMapper) {
		this.authenticationManager = authenticationManager;
		this.tokenProvider = tokenProvider;
		this.objectMapper = objectMapper;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
		throws AuthenticationException {
		LoginRequest loginRequest;
		try {
			String messageBody = StreamUtils.copyToString(request.getInputStream(), StandardCharsets.UTF_8);
			loginRequest = objectMapper.readValue(messageBody, LoginRequest.class);
		} catch (IOException e) {
			throw new CustomException(CommonErrorCode.INVALID_VALUE);
		}

		UsernamePasswordAuthenticationToken authToken =
			new UsernamePasswordAuthenticationToken(loginRequest.id(), loginRequest.password(), null);
		return authenticationManager.authenticate(authToken);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
		Authentication authentication) throws IOException {
		handleSuccessAuthentication(response, authentication);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
		AuthenticationException failed) throws IOException {
		handleFailureAuthentication(response);
	}

	private void handleSuccessAuthentication(HttpServletResponse response, Authentication authentication)
		throws IOException {

		CustomUserDetails userDetails = (CustomUserDetails)authentication.getPrincipal();

		String uid = userDetails.getUid();
		Long userId = userDetails.getUserId();

		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
		String role = authorities.stream()
			.findFirst()
			.map(GrantedAuthority::getAuthority)
			.orElseThrow(() -> new CustomException(AuthErrorCode.ACCESS_DENIED));

		UserTokenResponse loginToken;

		if (userDetails.getRole().equals(Role.ROLE_TEMP_USER)) {
			loginToken = tokenProvider.createTempLoginToken(uid, userId, userDetails.getRole());
		} else {
			loginToken = tokenProvider.createLoginToken(uid, userId, userDetails.getRole(),
				userDetails.getBusinessId());
		}

		LoginResponse loginResponse = LoginResponse.builder()
			.uid(userDetails.getUid())
			.role(role)
			.accessToken(loginToken.accessToken())
			.refreshToken(loginToken.refreshToken())
			.build();

		ResponseUtil.writeSuccessResponseWithHeaders(
			response,
			objectMapper,
			loginResponse,
			HttpStatus.OK
		);
	}

	private void handleFailureAuthentication(HttpServletResponse response) throws IOException {
		ResponseUtil.writeErrorResponse(response, objectMapper, AuthErrorCode.WRONG_ID_PW);
	}
}
