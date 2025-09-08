package laughcandidate.yellowribbonbe.badge.dto.response;

public record BadgeInfoResponse(
        Long badgeId,
        String category,
        BadgeApplyResponse apply
) {

}