package laughcandidate.yellowribbonbe.user.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {

	ADMIN("ROLE_ADMIN"), TEMP_USER("ROLE_TEMP_USER"), USER("ROLE_USER");

	private final String role;
}