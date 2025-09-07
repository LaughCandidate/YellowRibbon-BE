package laughcandidate.yellowribbonbe.global.exception.errorCode;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum AdminErrorCode implements ErrorCode {

	BADGE_APPLY_NOT_FOUND(HttpStatus.NOT_FOUND, "P-001", "신청 내역을 찾을 수 없습니다.");

	private HttpStatus httpStatus;
	private String code;
	private String message;
}
