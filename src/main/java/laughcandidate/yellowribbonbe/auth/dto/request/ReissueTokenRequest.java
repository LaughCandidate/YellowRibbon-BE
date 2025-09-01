package laughcandidate.yellowribbonbe.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

@Schema(name = "ReissueTokenRequest: 재발급 토큰 요청 Dto")
public record ReissueTokenRequest(
	@NotNull
	@Schema(description = "refresh 토큰입니다.", example = "refresh-token")
	String refreshToken
) {
}