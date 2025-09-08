package laughcandidate.yellowribbonbe.image.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(name = "GetPresignedUrlRequest: 이미지 정보 조회 요청 Dto")
public record GetPresignedUrlRequest(
	@NotBlank(message = "이미지 ID는 필수 입력값입니다.")
	@Schema(description = "이미지 ID 식별값", example = "1L")
	Long imageId
) {
}
