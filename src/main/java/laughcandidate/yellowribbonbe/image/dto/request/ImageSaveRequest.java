package laughcandidate.yellowribbonbe.image.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import laughcandidate.yellowribbonbe.image.entity.ImageType;

@Schema(name = "ImageSaveRequest: 이미지 정보 저장 요청 Dto")
public record ImageSaveRequest(
	@NotBlank(message = "미션 ID는 필수 입력값입니다.")
	@Schema(description = "미션 ID 식별값", example = "1L")
	Long missionId,

	@NotBlank(message = "이미지 식별값은 필수 입력값입니다.")
	@Schema(description = "이미지 식별값", example = "1vvwefwe")
	String uuid,

	@NotBlank(message = "원본명은 필수 입력값입니다.")
	@Schema(description = "원본명름", example = "검증 사진")
	String originalName,

	@NotBlank(message = "이미지 크기는 필수 입력값입니다.")
	@Schema(description = "이미지 크기", example = "12304")
	Integer size,

	@NotBlank(message = "확장자명은 필수 입력값입니다.")
	@Schema(description = "확장자명", example = "확장자")
	ImageType imageType
) {
}
