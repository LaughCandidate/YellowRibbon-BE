package laughcandidate.yellowribbonbe.product.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Schema(name = "CompareRequest: 상품 비교 요청 DTO")
@Getter
@NoArgsConstructor
public class CompareRequest {
    
    @Schema(description = "비교할 사용자 보유 상품 ID", example = "1")
    @NotNull(message = "사용자 보유 상품 ID는 필수입니다.")
    private Long myDataId;
}
