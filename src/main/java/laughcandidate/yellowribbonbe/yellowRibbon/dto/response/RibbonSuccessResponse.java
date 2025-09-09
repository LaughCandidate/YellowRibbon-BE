package laughcandidate.yellowribbonbe.yellowRibbon.dto.response;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;

public record RibbonSuccessResponse(
        Long yellowRibbonId,
        String season
) {
    public static RibbonSuccessResponse from(YellowRibbon ribbon) {
        return new RibbonSuccessResponse(
                ribbon.getId(),
                String.valueOf(ribbon.getSeason())
        );
    }
}
