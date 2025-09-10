package laughcandidate.yellowribbonbe.global.exception.errorCode;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum YellowRibbonErrorCode implements ErrorCode{

    // 404
    CURRENT_SEASON_RIBBON_NOT_FOUND(HttpStatus.NOT_FOUND, "YR-001", "해당 연도에 발급 받은 옐로 리본이 없습니다."),
    YELLOW_RIBBON_NOT_FOUND(HttpStatus.NOT_FOUND, "YR-002", "요청한 옐로 리본을 찾을 수 없습니다.");

    private HttpStatus httpStatus;
    private String code;
    private String message;
}
