package laughcandidate.yellowribbonbe.product.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.experimental.SuperBuilder;

@Schema(name = "BaseComparisonItem: 비교 항목 기본 클래스")
@Getter
@SuperBuilder
public abstract class BaseComparisonItem {
    
    @Schema(description = "사용자 상품 값", example = "연 4.20%")
    protected String userValue;
    
    @Schema(description = "혜택 상품 값", example = "연 3.31%")
    protected String benefitValue;
    
    @Schema(description = "차이값", example = "-0.89%p")
    protected String difference;
    
    @Schema(description = "혜택 상품이 더 좋은지 여부", example = "true")
    protected boolean isBetter;
}
