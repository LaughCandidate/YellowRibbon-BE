package laughcandidate.yellowribbonbe.global.exception.errorCode;

import org.springframework.http.HttpStatus;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum AdminErrorCode implements ErrorCode {

    // 404
    BADGE_APPLY_NOT_FOUND(HttpStatus.NOT_FOUND, "A001", "배지 신청을 찾을 수 없습니다."),
    YELLOW_RIBBON_NOT_FOUND(HttpStatus.NOT_FOUND, "A002", "현재 발급 가능한 리본을 찾을 수 없습니다.");

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;
}