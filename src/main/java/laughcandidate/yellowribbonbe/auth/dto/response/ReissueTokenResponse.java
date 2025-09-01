package laughcandidate.yellowribbonbe.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

@Schema(name = "ReissueTokenResponse: 재발급 토큰 응답 Dto")
public record ReissueTokenResponse(
	@NotNull
	@Schema(description = "access 토큰입니다.", example = "access-token")
	String accessToken,
	@NotNull
	@Schema(description = "refresh 토큰입니다.", example = "refresh-token")
	String refreshToken
) {}