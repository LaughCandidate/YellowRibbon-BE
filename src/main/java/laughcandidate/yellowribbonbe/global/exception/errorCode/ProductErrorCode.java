package laughcandidate.yellowribbonbe.global.exception.errorCode;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ProductErrorCode implements ErrorCode {

    // 400
    INVALID_PRODUCT_CATEGORY(HttpStatus.BAD_REQUEST, "P-001", "잘못된 상품 카테고리입니다: %s"),
    CATEGORY_MISMATCH(HttpStatus.BAD_REQUEST, "P-003", "비교하려는 상품들의 카테고리가 일치하지 않습니다."),
    INVALID_DATE_RANGE(HttpStatus.BAD_REQUEST, "P-004", "만기일자가 현재일자보다 과거입니다."),
    INVALID_CALCULATION_DATA(HttpStatus.BAD_REQUEST, "P-005", "계산에 필요한 데이터가 부족합니다: %s"),
    ZERO_OR_NEGATIVE_AMOUNT(HttpStatus.BAD_REQUEST, "P-006", "금액은 0보다 커야 합니다: %s"),
    INVALID_INTEREST_RATE(HttpStatus.BAD_REQUEST, "P-007", "금리는 0% 이상이어야 합니다."),
    INVALID_DATE_ORDER(HttpStatus.BAD_REQUEST, "P-008", "시작일자가 만기일자보다 늦습니다."),
    MISSING_REQUIRED_DATA(HttpStatus.BAD_REQUEST, "P-009", "필수 데이터가 누락되었습니다: %s"),
    
    // 404
    PRODUCT_NOT_FOUND(HttpStatus.NOT_FOUND, "P-002", "상품을 찾을 수 없습니다.");

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;
}
