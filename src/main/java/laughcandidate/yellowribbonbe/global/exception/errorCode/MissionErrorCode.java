package laughcandidate.yellowribbonbe.global.exception.errorCode;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum MissionErrorCode implements ErrorCode {

	// 400
	INVALID_PROMPT(HttpStatus.BAD_REQUEST, "M-002", "프롬프트가 비어있습니다."),
	INVALID_IMAGE_FILE(HttpStatus.BAD_REQUEST, "M-003", "이미지 파일은 필수입니다."),
	NOT_IMAGE_FILE(HttpStatus.BAD_REQUEST, "M-004", "JPEG, PNG, JPG 파일만 업로드 가능합니다."),
	FILE_SIZE_EXCEEDED(HttpStatus.BAD_REQUEST, "M-006", "파일 크기는 10MB를 초과할 수 없습니다."),
	MULTIPLE_FILES_NOT_ALLOWED(HttpStatus.BAD_REQUEST, "M-007", "이미지는 1개만 업로드할 수 있습니다."),

	// 404
	MISSION_NOT_FOUND(HttpStatus.NOT_FOUND, "M-001", "미션을 찾을 수 없습니다."),
	
	// 500
	AI_REQUEST_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "M-005", "AI 요청 처리 중 오류가 발생했습니다."),
	;

	private final HttpStatus httpStatus;
	private final String code;
	private final String message;
}
