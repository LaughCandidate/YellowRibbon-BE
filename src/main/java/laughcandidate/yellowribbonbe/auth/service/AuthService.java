package laughcandidate.yellowribbonbe.auth.service;

import static laughcandidate.yellowribbonbe.auth.constants.EmailVerificationConstant.*;
import static laughcandidate.yellowribbonbe.global.constants.TokenConstant.*;

import java.time.Duration;
import java.time.LocalDateTime;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import jakarta.transaction.Transactional;
import laughcandidate.yellowribbonbe.auth.dto.response.PhoneVerificationResultResponse;
import laughcandidate.yellowribbonbe.auth.dto.response.RegisterResponse;
import laughcandidate.yellowribbonbe.auth.dto.response.ReissueTokenResponse;
import laughcandidate.yellowribbonbe.auth.jwt.TokenProvider;
import laughcandidate.yellowribbonbe.auth.jwt.dto.UserTokenResponse;
import laughcandidate.yellowribbonbe.auth.util.GeneratorRandomUtil;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AuthErrorCode;
import laughcandidate.yellowribbonbe.user.entity.Role;
import laughcandidate.yellowribbonbe.user.entity.User;
import laughcandidate.yellowribbonbe.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

	private final EmailService emailService;
	private final UserRepository userRepository;
	private final RedisTemplate<String, String> redisTemplate;
	private final PasswordEncoder passwordEncoder;
	private final TokenProvider tokenProvider;

	public void checkPhoneDuplicate(String phone) {
		boolean isPhoneExists = userRepository.existsByPhone(phone);

		if (isPhoneExists) {
			throw new CustomException(AuthErrorCode.PHONE_DUPLICATED);
		}
	}

	@Transactional
	public PhoneVerificationResultResponse sendVerificationCode(String phone) {
		String code = GeneratorRandomUtil.generateRandomNum();
		LocalDateTime now = LocalDateTime.now();

		redisTemplate.opsForValue().set(PREFIX_VERIFICATION_CODE + phone, code, Duration.ofMinutes(VERIFICATION_TIME));
		redisTemplate.opsForValue()
			.set(PREFIX_VERIFICATION_TIME + phone, now.toString(), Duration.ofMinutes(VERIFICATION_TIME));
		String emailAddress = emailService.getServerEmail();

		return new PhoneVerificationResultResponse(code, emailAddress);
	}

	@Transactional
	public void verifyCode(String phone) {
		String code = redisTemplate.opsForValue().get(PREFIX_VERIFICATION_CODE + phone);
		String time = redisTemplate.opsForValue().get(PREFIX_VERIFICATION_TIME + phone);

		if (code == null || time == null) {
			throw new CustomException(AuthErrorCode.INVALID_VERIFICATION_CODE);
		}

		LocalDateTime createdAt = LocalDateTime.parse(time);
		boolean result = emailService.extractCodeByPhoneNumber(code, phone, createdAt);

		if (!result) {
			throw new CustomException(AuthErrorCode.INVALID_VERIFICATION_CODE);
		}

		redisTemplate.delete(PREFIX_VERIFICATION_CODE + phone);
		redisTemplate.delete(PREFIX_VERIFICATION_TIME + phone);

		redisTemplate.opsForValue().set(phone, VERIFIED, Duration.ofMinutes(VERIFICATION_TIME));
	}

	public RegisterResponse register(String name, String phone, String password) {
		String isVerified = redisTemplate.opsForValue().get(phone);

		if (isVerified == null || !isVerified.equals(VERIFIED)) {
			throw new CustomException(AuthErrorCode.ACCESS_DENIED);
		}

		String uid = GeneratorRandomUtil.generateRandomUid();

		User user = User.builder()
			.name(name)
			.phone(phone)
			.password(passwordEncoder.encode(password))
			.role(Role.TEMP_USER)
			.uid(uid)
			.build();

		userRepository.save(user);

		UserTokenResponse token = tokenProvider.createLoginToken(uid, user.getId(), user.getRole().getRole());

		return new RegisterResponse(uid, user.getRole().getRole(), token.accessToken(), token.refreshToken());
	}

	@Transactional
	public ReissueTokenResponse reissue(String refreshToken) {
		validateRefreshToken(refreshToken);
		String uid = extractUidFromToken(refreshToken);
		validateStoredRefreshToken(uid, refreshToken);
		User user = getUserByUid(uid);
		Long userId = getUserIdFromRedis(uid);

		UserTokenResponse newTokens = tokenProvider.createLoginToken(uid, userId, user.getRole().getRole());
		return new ReissueTokenResponse(newTokens.accessToken(), newTokens.refreshToken());
	}

	private void validateRefreshToken(String refreshToken) {
		if (!tokenProvider.validateToken(refreshToken)) {
			throw new CustomException(AuthErrorCode.INVALID_TOKEN);
		}
	}

	private String extractUidFromToken(String refreshToken) {
		Claims claims = tokenProvider.getClaimsFromToken(refreshToken);
		return claims.getSubject();
	}

	private void validateStoredRefreshToken(String uid, String refreshToken) {
		String storedRefreshToken = redisTemplate.opsForValue().get(REFRESH_TOKEN_PREFIX + uid);
		if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
			throw new CustomException(AuthErrorCode.REFRESH_TOKEN_NOT_FOUND);
		}
	}

	private User getUserByUid(String uid) {
		return userRepository.findByUid(uid)
			.orElseThrow(() -> new CustomException(AuthErrorCode.USER_NOT_FOUND));
	}

	private Long getUserIdFromRedis(String uid) {
		String userId = redisTemplate.opsForValue().get(USER_ID_PREFIX + uid);
		if (userId == null) {
			throw new CustomException(AuthErrorCode.ACCESS_DENIED);
		}
		return Long.parseLong(userId);
	}
}
