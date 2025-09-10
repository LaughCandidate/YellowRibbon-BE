package laughcandidate.yellowribbonbe.yellowRibbon.dto.response;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import lombok.Builder;

import java.util.ArrayList;
import java.util.List;

@Builder
public record RibbonSuccessListResponse(
        List<RibbonSuccessResponse> yellowRibbons
) {
    public static RibbonSuccessListResponse from(List<YellowRibbon> ribbons) {
        List<RibbonSuccessResponse> items = new ArrayList<>(ribbons.size());
        for (YellowRibbon ribbon : ribbons) {
            items.add(RibbonSuccessResponse.from(ribbon));
        }
        return RibbonSuccessListResponse.builder()
                .yellowRibbons(items)
                .build();
    }
}

