package laughcandidate.yellowribbonbe.auth.jwt;

import static laughcandidate.yellowribbonbe.global.constants.TokenConstant.*;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import laughcandidate.yellowribbonbe.auth.service.CustomUserDetails;
import laughcandidate.yellowribbonbe.auth.jwt.dto.UserTokenResponse;
import laughcandidate.yellowribbonbe.auth.util.BearerUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import laughcandidate.yellowribbonbe.auth.util.ResponseUtil;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AuthErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class TokenProvider {

	private final SecretKey secretKey;
	private final RedisTemplate<String, String> redisTemplate;

	public TokenProvider(@Value("${security.jwt.token.secret-key}") String secretKeyString,
		RedisTemplate<String, String> redisTemplate) {
		this.secretKey = Keys.hmacShaKeyFor(secretKeyString.getBytes(StandardCharsets.UTF_8));
		this.redisTemplate = redisTemplate;
	}

	public UserTokenResponse createLoginToken(final String uid, final Long userId, final String role) {

		String accessToken = createAccessToken(uid, role);
		String refreshToken = createRefreshToken(uid, role);

		saveRefreshToken(uid, refreshToken);
		saveUserId(uid, userId);

		return new UserTokenResponse(
			accessToken,
			refreshToken
		);
	}

	public String createAccessToken(final String uid, final String role) {
		return createToken(uid, role, ACCESS_TOKEN_EXPIRATION_MINUTE * MINUTE_IN_MILLISECONDS);
	}

	public String createRefreshToken(final String uid, final String role) {
		return createToken(uid, role, REFRESH_TOKEN_EXPIRATION_DAYS * DAYS_IN_MILLISECONDS);
	}

	public String resolveAccessToken(HttpServletRequest request) {
		Optional<String> accessToken = BearerUtil.extractBearerToken(request);
		if (!accessToken.isEmpty()) {
			return accessToken.get();
		}
		return null;
	}

	public boolean validateToken(final String token) {
		if (token == null) {
			return false;
		}
		try {
			parseToken(token);
			return true;
		} catch (SignatureException e) {
			log.error("잘못된 jwt 서명입니다.");
		} catch (MalformedJwtException e) {
			log.error("잘못된 jwt 토큰입니다.");
		} catch (ExpiredJwtException e) {
			log.error("만료된 jwt 토큰입니다.");
			throw e;
		} catch (UnsupportedJwtException e) {
			log.error("지원되지 않는 jwt 토큰입니다.");
		} catch (IllegalArgumentException e) {
			log.error("jwt 클레임 문자열이 비어 있습니다.");
		}
		return false;
	}

	public Authentication getAuthenticationByAccessToken(String accessToken, HttpServletResponse response, ObjectMapper objectMapper) throws java.io.IOException {
		Claims claims = getClaimsFromToken(accessToken);
		String uid = claims.getSubject();
		String role = claims.get("role", String.class);
		
		try {
			Long userId = getUserId(uid);
			CustomUserDetails customUserDetails = CustomUserDetails.fromClaims(uid, userId, role);
			return new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
		} catch (CustomException e) {
			ResponseUtil.writeErrorResponse(response, objectMapper, e.getErrorCode());
			return null;
		}
	}

	public Claims getClaimsFromToken(String token) {
		return getClaims(token);
	}

	private Claims getClaims(String token) {
		try {
			return Jwts.parser()
				.verifyWith(secretKey)
				.build()
				.parseSignedClaims(token)
				.getPayload();
		} catch (ExpiredJwtException e) {
			return e.getClaims();
		} catch (JwtException e) {
			throw new IllegalArgumentException("잘못된 jwt 토큰 입니다.");
		}
	}

	public void deleteRefreshToken(String uid) {
		redisTemplate.delete(uid);
	}

	public void deleteUserId(String uid) {
		redisTemplate.delete(uid);
	}

	private void saveRefreshToken(String uid, String refreshToken) {
		redisTemplate.opsForValue()
			.set(REFRESH_TOKEN_PREFIX + uid, refreshToken, REFRESH_TOKEN_EXPIRATION_DAYS, TimeUnit.DAYS);
	}

	private void saveUserId(String uid, Long userId) {
		redisTemplate.opsForValue()
			.set(USER_ID_PREFIX + uid, userId.toString(), ACCESS_TOKEN_EXPIRATION_MINUTE, TimeUnit.MINUTES);
	}

	private Long getUserId(String uid) {
		String userId = redisTemplate.opsForValue().get(USER_ID_PREFIX + uid);
		if (userId == null) {
			throw new CustomException(AuthErrorCode.USER_NOT_FOUND);
		}
		return Long.valueOf(userId);
	}

	private String createToken(final String uid, final String role, final long expireLength) {
		Date now = new Date();
		Date validity = new Date(now.getTime() + expireLength);

		return Jwts.builder()
			.subject(uid)
			.claim("role", role)
			.issuedAt(now)
			.expiration(validity)
			.signWith(secretKey)
			.compact();
	}

	private Claims parseToken(final String token) {
		return Jwts.parser()
			.verifyWith(secretKey)
			.build()
			.parseSignedClaims(token)
			.getPayload();
	}
}