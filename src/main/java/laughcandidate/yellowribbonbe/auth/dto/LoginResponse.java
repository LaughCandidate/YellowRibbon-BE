package laughcandidate.yellowribbonbe.auth.dto;

import lombok.Builder;

@Builder
public record LoginResponse(
    String uid,
    String role,
    String accessToken,
    String refreshToken
) {
}