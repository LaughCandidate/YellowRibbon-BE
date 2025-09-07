package laughcandidate.yellowribbonbe.badge.dto.response;

import java.util.List;

import org.springframework.data.domain.Page;

import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import lombok.Builder;

@Builder
public record BadgeApplyListResponse(
	List<BadgeApplyListItemResponse> badgeApplies,
	int currentPage,
	int totalPages,
	long totalElements,
	int size,
	boolean hasNext,
	boolean hasPrevious
) {
	public static BadgeApplyListResponse from(Page<BadgeApply> badgeApplyPage) {
		List<BadgeApplyListItemResponse> items = badgeApplyPage.getContent()
			.stream()
			.map(BadgeApplyListItemResponse::from)
			.toList();

		return BadgeApplyListResponse.builder()
			.badgeApplies(items)
			.currentPage(badgeApplyPage.getNumber())
			.totalPages(badgeApplyPage.getTotalPages())
			.totalElements(badgeApplyPage.getTotalElements())
			.size(badgeApplyPage.getSize())
			.hasNext(badgeApplyPage.hasNext())
			.hasPrevious(badgeApplyPage.hasPrevious())
			.build();
	}
}
