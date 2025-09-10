package laughcandidate.yellowribbonbe.product.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

@Schema(name = "ProductSummary: 상품 요약 DTO")
@Getter
@Builder
public class ProductSummary {
    
    @Schema(description = "상품명", example = "옐로우리본 대출")
    private String productName;
    
    @Schema(description = "상품 카테고리", example = "대출")
    private String category;
    
    @Schema(description = "주요 혜택 요약", example = "최대 50,000원 이익")
    private String mainBenefit;
}
