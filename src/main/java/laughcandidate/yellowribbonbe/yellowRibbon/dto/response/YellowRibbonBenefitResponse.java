package laughcandidate.yellowribbonbe.yellowRibbon.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonBenefit;

@Schema(description = "옐로 리본 혜택 정보")
public record YellowRibbonBenefitResponse(
        @Schema(description = "혜택 ID")
        Long yellowRibbonBenefitId,

        @Schema(description = "혜택명")
        String name,

        @Schema(description = "혜택 설명")
        String description,

        @Schema(description = "연결 링크")
        String linkUrl
) {
    public static YellowRibbonBenefitResponse from(YellowRibbonBenefit b) {
        return new YellowRibbonBenefitResponse(
                b.getId(),
                b.getName(),
                b.getDescription(),
                b.getLinkUrl()
        );
    }

}
