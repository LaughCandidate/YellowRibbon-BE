package laughcandidate.yellowribbonbe.product.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.experimental.SuperBuilder;

@Schema(name = "GraphComparisonItem: 그래프용 비교 항목 DTO")
@Getter
@SuperBuilder
public class GraphComparisonItem extends BaseComparisonItem {
    
    @Schema(description = "사용자 상품 점수 (0-100)", example = "23")
    private int userScore;
    
    @Schema(description = "혜택 상품 점수 (0-100)", example = "71")
    private int benefitScore;
}
