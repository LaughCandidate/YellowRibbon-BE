package laughcandidate.yellowribbonbe.yellowRibbon.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonBenefit;
import lombok.Builder;

import java.util.ArrayList;
import java.util.List;

@Builder
public record YellowRibbonBenefitListResponse(
        @Schema(description = "옐로 리본 혜택 리스트")
        List<YellowRibbonBenefitResponse> yellowRibbonBenefits
) {
    public static YellowRibbonBenefitListResponse from(List<YellowRibbonBenefit> benefits) {
        List<YellowRibbonBenefitResponse> items = new ArrayList<>(benefits.size());
        for (YellowRibbonBenefit b : benefits) {
            items.add(YellowRibbonBenefitResponse.from(b));
        }

        return YellowRibbonBenefitListResponse.builder()
                .yellowRibbonBenefits(items)
                .build();
    }
}
