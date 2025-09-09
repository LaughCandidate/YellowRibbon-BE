package laughcandidate.yellowribbonbe.admin.dto.response;

import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import lombok.Builder;
import org.springframework.data.domain.Page;

import java.util.List;

@Builder
public record BadgeApplyListResponse(
        List<BadgeApplyListItemBasicResponse> badgeApplies,
        int currentPage,
        int totalPages,
        long totalElements,
        int size,
        boolean hasNext,
        boolean hasPrevious
) {
    public static BadgeApplyListResponse from(Page<BadgeApply> page) {
        List<BadgeApplyListItemBasicResponse> badgeApplies = page.getContent()
                .stream()
                .map(BadgeApplyListItemBasicResponse::from)
                .toList();

        return BadgeApplyListResponse.builder()
                .badgeApplies(badgeApplies)
                .currentPage(page.getNumber())
                .totalPages(page.getTotalPages())
                .totalElements(page.getTotalElements())
                .size(page.getSize())
                .hasNext(page.hasNext())
                .hasPrevious(page.hasPrevious())
                .build();
    }
}