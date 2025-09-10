package laughcandidate.yellowribbonbe.product.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.experimental.SuperBuilder;

@Schema(name = "TableComparisonItem: 표용 비교 항목 DTO")
@Getter
@SuperBuilder
public class TableComparisonItem extends BaseComparisonItem {
}
