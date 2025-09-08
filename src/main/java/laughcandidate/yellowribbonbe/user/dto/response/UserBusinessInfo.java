package laughcandidate.yellowribbonbe.user.dto.response;

public record UserBusinessInfo(
	Long userId,
	String uid,
	String id,
	String password,
	String role,
	Long businessId
) {
}
