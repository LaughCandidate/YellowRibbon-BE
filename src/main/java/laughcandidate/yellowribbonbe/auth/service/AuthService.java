package laughcandidate.yellowribbonbe.auth.service;

import java.time.Duration;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import laughcandidate.yellowribbonbe.auth.dto.response.PhoneVerificationResultResponse;
import laughcandidate.yellowribbonbe.auth.util.GeneratorRandomUtil;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AuthErrorCode;
import laughcandidate.yellowribbonbe.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

	private final EmailService emailService;
	private final UserRepository userRepository;
	private final RedisTemplate<String, String> redisTemplate;

	public void checkPhoneDuplicate(String phone) {
		boolean isPhoneExists = userRepository.existsByPhone(phone);

		if (isPhoneExists) {
			throw new CustomException(AuthErrorCode.PHONE_DUPLICATED);
		}
	}

	public PhoneVerificationResultResponse sendVerificationCode(String phone) {
		String code = GeneratorRandomUtil.generateRandomNum();

		redisTemplate.opsForValue().set(phone, code, Duration.ofMinutes(5));
		String emailAddress = emailService.getServerEmail();

		return new PhoneVerificationResultResponse(code,emailAddress);
	}
}
