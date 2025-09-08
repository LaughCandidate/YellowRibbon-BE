package laughcandidate.yellowribbonbe.product.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

import java.math.BigDecimal;

@Schema(name = "ProductListResponse: 금융상품 리스트 조회 응답 Dto")
@Getter
@Builder
public class ProductListResponse {
    @Schema(description = "상품 ID(공통)", example = "1")
    private Long productId;

    @Schema(description = "배지 카테고리(공통)", example = "사회적 포용")
    private String badgeCategory;

    @Schema(description = "상품명(공통)", example = "옐로우리본 대출")
    private String productName;

    @Schema(description = "상품 설명(공통)", example = "소상공인을 위한 특별 대출 상품")
    private String description;

    @Schema(description = "상품 카테고리(공통)", example = "LOAN")
    private String category;
    
    // 상품별 특화 정보
    @Schema(description = "금리(대출, 예금, 적금)", example = "3.51%")
    private String interestRate;

    @Schema(description = "대출 한도(대출)", example = "5000만원")
    private String loanLimit;

    @Schema(description = "보험 보장 유형(보험)", example = "종합보장형")
    private String coverageType;
    
    @Schema(description = "표시 기간(예금, 적금)", example = "12개월")
    private String displayPeriod;
}
