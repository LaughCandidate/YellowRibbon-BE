package laughcandidate.yellowribbonbe.global.exception.errorCode;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum UserErrorCode implements ErrorCode{

	USER_NOT_FOUND(HttpStatus.NOT_FOUND, "U-001", "유저가 존재하지 않습니다.")
	;

	private final HttpStatus httpStatus;
	private final String code;
	private final String message;
}
