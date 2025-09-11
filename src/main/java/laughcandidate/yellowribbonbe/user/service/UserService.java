package laughcandidate.yellowribbonbe.user.service;

import static laughcandidate.yellowribbonbe.global.exception.errorCode.AuthErrorCode.*;

import org.springframework.stereotype.Service;

import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.user.dto.response.UserInfoResponse;
import laughcandidate.yellowribbonbe.user.entity.User;
import laughcandidate.yellowribbonbe.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

	private final UserRepository userRepository;

	public UserInfoResponse getUserInfo(String uid) {

		User user = userRepository.findByUid(uid)
			.orElseThrow(() -> new CustomException(USER_NOT_FOUND));

		return new UserInfoResponse(user.getName());
	}
}
