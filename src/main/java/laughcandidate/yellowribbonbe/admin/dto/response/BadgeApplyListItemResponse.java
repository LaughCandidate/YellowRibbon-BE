package laughcandidate.yellowribbonbe.admin.dto.response;

import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.badge.entity.Category;
import laughcandidate.yellowribbonbe.global.entity.Status;
import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record BadgeApplyListItemResponse(
        Long badgeApplyId,
        Status status,
        String applicantName,
        String applicantPhone,
        String businessName,
        String businessNo,
        Category badgeCategory,
        LocalDateTime appliedAt
) {
    public static BadgeApplyListItemResponse from(BadgeApply badgeApply) {
        return BadgeApplyListItemResponse.builder()
                .badgeApplyId(badgeApply.getId())
                .status(badgeApply.getStatus())
                .applicantName(badgeApply.getUser().getName())
                .applicantPhone(badgeApply.getUser().getPhone())
                .businessName(badgeApply.getBusiness().getBusinessName())
                .businessNo(badgeApply.getBusiness().getBusinessNo())
                .badgeCategory(badgeApply.getBadge().getCategory())
                .appliedAt(badgeApply.getCreatedAt())
                .build();
    }
}