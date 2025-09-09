package laughcandidate.yellowribbonbe.product.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

@Schema(name = "ProductDetailResponse: 금융상품 상세 조회 응답 Dto")
@Getter
@Builder
public class ProductDetailResponse {
    @Schema(description = "상품 ID", example = "1")
    private Long productId;

    @Schema(description = "상품명", example = "사회적 포용 맞춤한 신용대출")
    private String productName;

    @Schema(description = "상품 설명", example = "따뜻한 사장님을 위한 사업자 신용대출")
    private String description;

    @Schema(description = "상품 카테고리", example = "LOAN")
    private String category;
    
    // 대출, 예금, 적금 공통 - 최소/최대 금리
    @Schema(description = "최소 금리 (대출/예금/적금)", example = "연 3.31%")
    private String minInterestRate;
    
    @Schema(description = "최대 금리 (대출/예금/적금)", example = "5.62%")
    private String maxInterestRate;

    // 대출 전용
    @Schema(description = "대출 한도 (대출)", example = "2억원")
    private String loanLimit;

    // 예금 전용  
    @Schema(description = "최소 예치금 (예금)", example = "100만원")
    private String minDeposit;

    // 적금 전용
    @Schema(description = "최소 저축 금액 (적금)", example = "월 1만원")
    private String minSavingsAmount;

    @Schema(description = "최대 저축 금액 (적금)", example = "30만원")
    private String maxSavingsAmount;

    // 보험 전용
    @Schema(description = "월 보험료 (보험)", example = "30,000원부터")
    private String monthlyPremium;

    @Schema(description = "보장 기간 (보험)", example = "1년 (자동 갱신)")
    private String coveragePeriod;
}