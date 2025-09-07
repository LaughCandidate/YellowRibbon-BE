package laughcandidate.yellowribbonbe.admin.dto.response;

import com.fasterxml.jackson.annotation.JsonFormat;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record RibbonIssueListItemResponse(
        Long ribbonSuccessId,
        String businessName,
        String businessNo,
        @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
        LocalDateTime issuedAt
) {
    public static RibbonIssueListItemResponse from(YellowRibbonSuccess yellowRibbonSuccess) {
        return RibbonIssueListItemResponse.builder()
                .ribbonSuccessId(yellowRibbonSuccess.getId())
                .businessName(yellowRibbonSuccess.getBusiness().getBusinessName())
                .businessNo(yellowRibbonSuccess.getBusiness().getBusinessNo())
                .issuedAt(yellowRibbonSuccess.getCreatedAt())
                .build();
    }
}