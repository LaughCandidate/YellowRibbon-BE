package laughcandidate.yellowribbonbe.auth.service;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import laughcandidate.yellowribbonbe.user.entity.User;
import laughcandidate.yellowribbonbe.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	public CustomUserDetails loadUserByUsername(String loginId) throws UsernameNotFoundException {
		Optional<User> user = userRepository.findByLoginIdAndIsDeletedFalse(loginId);

		if (user.isPresent()) {
			User loginUser = user.get();
			return new CustomUserDetails(loginUser.getUid(), loginUser.getId(), loginUser.getPassword(),
				loginUser.getRole().getRole());
		}
		return null;
	}
}