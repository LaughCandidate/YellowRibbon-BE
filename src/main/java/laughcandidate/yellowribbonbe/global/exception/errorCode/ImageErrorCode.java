package laughcandidate.yellowribbonbe.global.exception.errorCode;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ImageErrorCode implements ErrorCode{

	// 404
	IMAGE_NOT_FOUND(HttpStatus.NOT_FOUND, "I-001", "존재하지 않는 이미지입니다."),
	;

	private HttpStatus httpStatus;
	private String code;
	private String message;
}
