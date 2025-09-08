package laughcandidate.yellowribbonbe.user.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {

	ROLE_ADMIN("ROLE_ADMIN"), ROLE_TEMP_USER("ROLE_TEMP_USER"), ROLE_USER("ROLE_USER");

	private final String role;
}