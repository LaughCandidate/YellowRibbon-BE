package laughcandidate.yellowribbonbe.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

@Schema(name = "RegisterResponse: 회원가입 응답 Dto")
public record RegisterResponse(
	@Schema(description = "유저 식별 값입니다,", example = "1fq23")
	String uid,
	@Schema(description = "로그인 성공한 유저의 권한입니다.", example = "ADMIN")
	String role,
	@NotNull
	@Schema(description = "JWT Access 토큰입니다.", example = "accessToken")
	String accessToken,
	@NotNull
	@Schema(description = "JWT Refresh 토큰입니다.", example = "refreshToken")
	String refreshToken
) {
}
