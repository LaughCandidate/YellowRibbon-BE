package laughcandidate.yellowribbonbe.global.exception.errorCode;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum BadgeErrorCode implements ErrorCode {

    // 404
    BADGE_NOT_FOUND(HttpStatus.NOT_FOUND, "BA-001", "존재하지 않는 배지입니다.");

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;
}
