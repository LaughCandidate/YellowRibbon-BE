package laughcandidate.yellowribbonbe.global.exception.errorCode;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum MyDataErrorCode implements ErrorCode {

    // 400
    INVALID_MYDATA_CATEGORY(HttpStatus.BAD_REQUEST, "MD-001", "잘못된 마이데이터 카테고리입니다: %s"),
    
    // 404
    MYDATA_NOT_FOUND(HttpStatus.NOT_FOUND, "MD-002", "보유하신 금융상품이 없습니다."),
    MYDATA_CATEGORY_NOT_FOUND(HttpStatus.NOT_FOUND, "MD-003", "%s 상품을 보유하고 있지 않습니다.");

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;
}
