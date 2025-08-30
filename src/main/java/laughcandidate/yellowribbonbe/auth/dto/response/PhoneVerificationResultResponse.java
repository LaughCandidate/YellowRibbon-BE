package laughcandidate.yellowribbonbe.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;

@Schema(name = "PhoneVerificationResultResponse: 전화번호 인증 정보 응답 Dto")
public record PhoneVerificationResultResponse(
	@Schema(description = "인증 번호", example = "1djnf3jk3f")
	String code,

	@Email
	@Schema(description = "서버 이메일 주소", example = "laughcandidate.verify@gmail.com")
	String emailAddress
) {
}