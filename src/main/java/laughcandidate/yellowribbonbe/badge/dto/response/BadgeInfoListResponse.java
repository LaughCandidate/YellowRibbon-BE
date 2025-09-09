package laughcandidate.yellowribbonbe.badge.dto.response;

import java.util.List;

public record BadgeInfoListResponse(
        List<BadgeInfoResponse> badges,
		SummaryBadgeInfoResponse summary
) {

}
