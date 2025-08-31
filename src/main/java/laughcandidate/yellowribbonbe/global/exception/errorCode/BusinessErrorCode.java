package laughcandidate.yellowribbonbe.global.exception.errorCode;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum BusinessErrorCode implements ErrorCode{

	// 404
	BUSINESS_NOT_FOUND(HttpStatus.NOT_FOUND, "B-001", "존재하지 않는 사업자입니다."),

	// 409
	BUSINESS_NO_DUPLICATED(HttpStatus.CONFLICT, "B-002", "이미 존재하는 사업자 번호입니다."),
	;

	private HttpStatus httpStatus;
	private String code;
	private String message;
}
