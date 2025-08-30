package laughcandidate.yellowribbonbe.auth.service;

import org.springframework.stereotype.Service;

import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AuthErrorCode;
import laughcandidate.yellowribbonbe.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

	private final UserRepository userRepository;

	public void checkPhoneDuplicate(String phone) {
		boolean isPhoneExists = userRepository.existsByPhone(phone);

		if (isPhoneExists) {
			throw new CustomException(AuthErrorCode.PHONE_DUPLICATED);
		}
	}
}
