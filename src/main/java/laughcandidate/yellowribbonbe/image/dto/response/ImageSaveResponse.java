package laughcandidate.yellowribbonbe.image.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(name = "ImageSaveResponse: 이미지 정보 저장 응답 Dto")
public record ImageSaveResponse(
	@NotBlank(message = "이미지 ID는 필수 응답값입니다.")
	@Schema(description = "이미지 제출 ID 식별값", example = "1L")
	Long imageId
) {
}
