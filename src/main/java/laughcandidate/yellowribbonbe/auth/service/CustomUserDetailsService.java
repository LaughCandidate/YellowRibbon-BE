package laughcandidate.yellowribbonbe.auth.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import laughcandidate.yellowribbonbe.user.dto.response.UserBusinessInfo;
import laughcandidate.yellowribbonbe.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	public CustomUserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
		UserBusinessInfo userBusinessInfo = userRepository.findUserBusinessInfoWithId(id);

		if (userBusinessInfo != null) {
			return new CustomUserDetails(
				userBusinessInfo.uid(),
				userBusinessInfo.userId(),
				userBusinessInfo.password(),
				userBusinessInfo.role(),
				userBusinessInfo.businessId()
			);
		}
		return null;
	}
}