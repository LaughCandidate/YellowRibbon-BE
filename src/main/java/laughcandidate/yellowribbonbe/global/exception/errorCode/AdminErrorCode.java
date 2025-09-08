package laughcandidate.yellowribbonbe.global.exception.errorCode;

import laughcandidate.yellowribbonbe.global.exception.errorCode.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum AdminErrorCode implements ErrorCode {
    BADGE_APPLY_NOT_FOUND("ADMIN_001", "배지 신청을 찾을 수 없습니다.", HttpStatus.NOT_FOUND);

    private final String code;
    private final String message;
    private final HttpStatus status;

    @Override
    public HttpStatus getHttpStatus() {
        return status;
    }
}