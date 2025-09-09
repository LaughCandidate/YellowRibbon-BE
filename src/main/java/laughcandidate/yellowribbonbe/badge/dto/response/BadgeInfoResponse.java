package laughcandidate.yellowribbonbe.badge.dto.response;

import laughcandidate.yellowribbonbe.badge.entity.Category;
import laughcandidate.yellowribbonbe.global.entity.Status;

public record BadgeInfoResponse(
        Long badgeId,
        Category category,
        Long totalMissionCount,
        Long successMissionCount,
        Status status
) {

}