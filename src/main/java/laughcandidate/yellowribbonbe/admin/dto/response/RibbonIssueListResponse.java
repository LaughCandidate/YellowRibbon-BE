package laughcandidate.yellowribbonbe.admin.dto.response;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import lombok.Builder;
import org.springframework.data.domain.Page;

import java.util.List;

@Builder
public record RibbonIssueListResponse(
        List<RibbonIssueListItemResponse> ribbonIssues,
        int currentPage,
        int totalPages,
        long totalElements,
        int size,
        boolean hasNext,
        boolean hasPrevious
) {
    public static RibbonIssueListResponse from(Page<YellowRibbonSuccess> page) {
        List<RibbonIssueListItemResponse> ribbonIssues = page.getContent()
                .stream()
                .map(RibbonIssueListItemResponse::from)
                .toList();

        return RibbonIssueListResponse.builder()
                .ribbonIssues(ribbonIssues)
                .currentPage(page.getNumber())
                .totalPages(page.getTotalPages())
                .totalElements(page.getTotalElements())
                .size(page.getSize())
                .hasNext(page.hasNext())
                .hasPrevious(page.hasPrevious())
                .build();
    }
}