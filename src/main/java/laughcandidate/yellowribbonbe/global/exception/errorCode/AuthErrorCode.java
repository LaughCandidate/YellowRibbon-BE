package laughcandidate.yellowribbonbe.global.exception.errorCode;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum AuthErrorCode implements ErrorCode {

	// 400
	INVALID_VERIFICATION_CODE(HttpStatus.BAD_REQUEST, "A-008", "유효하지 않은 인증번호입니다."),

	// 401
	WRONG_ID_PW(HttpStatus.UNAUTHORIZED, "A-001", "아이디 혹은 비밀번호가 올바르지 않습니다."),
	INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "A-002", "유효하지 않은 토큰입니다."),
	TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "A-003", "토큰이 만료되었습니다."),

	// 403
	INCORRECT_CLAIM_TOKEN(HttpStatus.FORBIDDEN, "A-004", "잘못된 토큰입니다."),
	ACCESS_DENIED(HttpStatus.FORBIDDEN, "A-005", "접근이 거부되었습니다."),

	// 404
	USER_NOT_FOUND(HttpStatus.NOT_FOUND, "A-006", "회원을 찾을 수 없습니다."),
	REFRESH_TOKEN_NOT_FOUND(HttpStatus.NOT_FOUND, "A-008", "리프레시 토큰을 찾을 수 없습니다."),

	// 409
	PHONE_DUPLICATED(HttpStatus.CONFLICT, "A-007", "이미 존재하는 전화번호입니다."),
	;

	private HttpStatus httpStatus;
	private String code;
	private String message;
}
