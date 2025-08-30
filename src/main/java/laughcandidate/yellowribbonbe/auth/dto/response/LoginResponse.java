package laughcandidate.yellowribbonbe.auth.dto.response;

import lombok.Builder;

@Builder
public record LoginResponse(
    String uid,
    String role,
    String accessToken,
    String refreshToken
) {
}