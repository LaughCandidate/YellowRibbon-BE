package laughcandidate.yellowribbonbe.admin.dto.response;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record RibbonIssueListItemResponse(
        Long ribbonSuccessId,
        String businessName,
        String businessNo,
        LocalDateTime issuedAt
) {
    public static RibbonIssueListItemResponse from(YellowRibbonSuccess ribbonSuccess) {
        return RibbonIssueListItemResponse.builder()
                .ribbonSuccessId(ribbonSuccess.getId())
                .businessName(ribbonSuccess.getBusiness().getBusinessName())
                .businessNo(ribbonSuccess.getBusiness().getBusinessNo())
                .issuedAt(ribbonSuccess.getCreatedAt())
                .build();
    }
}