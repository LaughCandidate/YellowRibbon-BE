package laughcandidate.yellowribbonbe.badge.dto.response;

import laughcandidate.yellowribbonbe.badge.entity.Category;

public record BadgeInfoResponse(
        Long badgeId,
        Category category,
        Long totalMissionCount,
        Long successMissionCount,
        String status
) {

}