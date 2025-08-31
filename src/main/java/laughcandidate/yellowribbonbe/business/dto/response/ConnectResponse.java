package laughcandidate.yellowribbonbe.business.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

@Schema(name = "ConnectResponse: 임시회원의 사업자 연동 응답 Dto")
public record ConnectResponse(
	@NotNull(message = "마지막 값 여부는 필수 입력값입니다.")
	@Schema(description = "마지막 값 여부", example = "true")
	boolean isLast,

	@Schema(description = "AT", example = "accessToken")
	String accessToken,

	@Schema(description = "RT", example = "refreshToken")
	String refreshToken
) {
}
