package laughcandidate.yellowribbonbe.badge.dto.response;

public record BadgeIssuanceResponse(
        Long badgeApplyId,
        Long businessId,
        Long badgeId,
        String status
) {
}
