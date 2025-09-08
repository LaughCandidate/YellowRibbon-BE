package laughcandidate.yellowribbonbe.product.dto;

import lombok.Builder;
import lombok.Getter;

import java.math.BigDecimal;

@Getter
@Builder
public class ProductListResponse {
    private Long productId;
    private String badgeCategory;
    private String productName;
    private String description;
    private String category;
    
    // 상품별 특화 정보
    private String interestRate;        // 공통: 대출, 예금, 적금
    private String loanLimit;           // 대출 전용
    private String coverageType;        // 보험 전용
    
    // 12개월 기준 표시용 (예금, 적금)
    private String displayPeriod;
}
