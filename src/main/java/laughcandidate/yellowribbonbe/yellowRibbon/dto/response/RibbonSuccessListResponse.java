package laughcandidate.yellowribbonbe.yellowRibbon.dto.response;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import lombok.Builder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Builder
public record RibbonSuccessListResponse(
        List<RibbonSuccessResponse> yellowRibbons,
        String message // 보유 리본이 없을 경우 보내는 메시지
) {
    public static RibbonSuccessListResponse from(List<YellowRibbon> ribbons) {
        List<RibbonSuccessResponse> items = new ArrayList<>(ribbons.size());
        for (YellowRibbon ribbon : ribbons) {
            items.add(RibbonSuccessResponse.from(ribbon));
        }
        return RibbonSuccessListResponse.builder()
                .yellowRibbons(items)
                .message(null)
                .build();
    }

    public static RibbonSuccessListResponse empty(String message) {
        return RibbonSuccessListResponse.builder()
                .yellowRibbons(Collections.emptyList())
                .message(message)
                .build();
    }
}

