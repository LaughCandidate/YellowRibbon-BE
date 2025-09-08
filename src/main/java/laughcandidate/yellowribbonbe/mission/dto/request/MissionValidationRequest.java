package laughcandidate.yellowribbonbe.mission.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

public record MissionValidationRequest(
	@NotNull(message = "이미지 ID는 필수입니다.")
	@Schema(description = "이미지 ID 식별값", example = "1L")
	Long imageId
) {
}