package laughcandidate.yellowribbonbe.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

@Schema(name = "RegisterRequest: 회원가입 요청 Dto")
public record RegisterRequest(
	@NotBlank
	@Schema(description = "이름", example = "김돌돌")
	String name,

	@NotBlank(message = "휴대전화 번호는 필수 입력값입니다.")
	@Pattern(regexp = "^010\\d{8}$", message = "전화번호는 010으로 시작하는 11자리 숫자여야 합니다.")
	@Schema(description = "휴대전화 번호", example = "01012341234")
	String phone,

	@NotBlank(message = "아이디는 필수 입력값입니다.")
	@Pattern(
		regexp = "^(?=\\d{6}$)(?!.*(?:012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210))(?!.*(.)\\1\\1)\\d{6}$",
		message = "아이디는 6자리 숫자이며, 3자 이상 연속되거나 반복되는 숫자는 사용할 수 없습니다."
	)
	@Schema(
		description = "아이디 (6자리 숫자, 연속/반복 숫자 3자 이상 금지)",
		example = "135790",
		pattern = "^\\d{6}$"
	)
	String id,

	@NotBlank(message = "간편비밀번호는 필수 입력값입니다.")
	@Pattern(
		regexp = "^(?=\\d{6}$)(?!.*(?:012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210))(?!.*(.)\\1\\1)\\d{6}$",
		message = "간편비밀번호는 6자리 숫자이며, 3자 이상 연속되거나 반복되는 숫자는 사용할 수 없습니다."
	)
	@Schema(
		description = "간편비밀번호 (6자리 숫자, 연속/반복 숫자 3자 이상 금지)",
		example = "135790",
		pattern = "^\\d{6}$"
	)
	String password
) {
}