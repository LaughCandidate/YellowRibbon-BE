package laughcandidate.yellowribbonbe.mission.dto.request;

import org.springframework.web.multipart.MultipartFile;

import jakarta.validation.constraints.NotNull;
import laughcandidate.yellowribbonbe.global.validation.ContentType;
import laughcandidate.yellowribbonbe.global.validation.FileSize;

public record MissionValidationRequest(
	@NotNull(message = "이미지 파일은 필수입니다.")
	@ContentType(
		allowed = {"image/jpeg", "image/png", "image/gif", "image/webp"},
		message = "이미지 파일만 업로드 가능합니다. (JPG, PNG, GIF, WEBP)"
	)
	@FileSize(
		max = "5MB",
		message = "이미지 파일 크기는 5MB 이하여야 합니다."
	)
	MultipartFile image
) {
}