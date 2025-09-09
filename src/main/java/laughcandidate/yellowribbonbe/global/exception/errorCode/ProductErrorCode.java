package laughcandidate.yellowribbonbe.global.exception.errorCode;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ProductErrorCode implements ErrorCode {

    // 400
    INVALID_PRODUCT_CATEGORY(HttpStatus.BAD_REQUEST, "P-001", "잘못된 상품 카테고리입니다: %s");

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;
}
