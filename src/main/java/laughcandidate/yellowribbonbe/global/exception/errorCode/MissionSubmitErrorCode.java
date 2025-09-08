package laughcandidate.yellowribbonbe.global.exception.errorCode;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum MissionSubmitErrorCode implements ErrorCode {

	// 404
	MISSION_SUBMIT_NOT_FOUND(HttpStatus.NOT_FOUND, "MS-001", "미션 제출을 찾을 수 없습니다."),
	;

	private final HttpStatus httpStatus;
	private final String code;
	private final String message;
}