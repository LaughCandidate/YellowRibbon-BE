package laughcandidate.yellowribbonbe.business.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import laughcandidate.yellowribbonbe.user.entity.Role;

@Schema(name = "ConnectResponse: 임시회원의 사업자 연동 응답 Dto")
public record ConnectResponse(

	@Schema(description = "AT", example = "accessToken")
	String accessToken,

	@Schema(description = "RT", example = "refreshToken")
	String refreshToken,

	@Schema(description = "Role", example = "ROLE_USER")
	Role role,

	@Schema(description = "businessId", example = "1L")
	Long businessId
) {
}
