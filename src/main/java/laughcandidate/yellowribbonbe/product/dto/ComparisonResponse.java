package laughcandidate.yellowribbonbe.product.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;

@Schema(name = "ComparisonResponse: 상품 비교 결과 DTO")
@Getter
@Builder
public class ComparisonResponse {
    
    @Schema(description = "상품 카테고리", example = "대출")
    private String category;
    
    @Schema(description = "그래프용 데이터 (0-100 점수)")
    private Map<String, GraphComparisonItem> graphData;
    
    @Schema(description = "표용 데이터 (실제 값)")
    private Map<String, TableComparisonItem> tableData;
    
    @Schema(description = "사용자 상품 요약")
    private ProductSummary userProduct;
    
    @Schema(description = "혜택 상품 요약")
    private ProductSummary benefitProduct;
}
