package laughcandidate.yellowribbonbe.business.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(name = "ConnectRequest: 임시 사업자 연동 요청 Dto")
public record ConnectRequest(
	@NotBlank(message = "사업자 번호는 필수 입력값입니다.")
	@Schema(description = "사업자 번호", example = "12345678")
	String businessNo,

	@NotBlank(message = "대표자명은 필수 입력값입니다.")
	@Schema(description = "대표자 이름", example = "김돌돌")
	String ownerName,

	@NotBlank(message = "개업일자는 필수 입력값입니다.")
	@Schema(description = "개업일자", example = "20250101")
	String startDate,

	@NotBlank(message = "사업자명은 필수 입력값입니다.")
	@Schema(description = "사업자 이름", example = "돌돌")
	String businessName
) {
}
