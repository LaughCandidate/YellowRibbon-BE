package laughcandidate.yellowribbonbe.admin.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import laughcandidate.yellowribbonbe.admin.dto.response.BadgeApplyListResponse;
import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.badge.entity.Status;
import laughcandidate.yellowribbonbe.badge.repository.BadgeApplyRepository;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AdminErrorCode;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AdminBadgeService {

	private final BadgeApplyRepository badgeApplyRepository;

	@Transactional(readOnly = true)
	public BadgeApplyListResponse getBadgeApplies(Status status, Pageable pageable) {
		Page<BadgeApply> badgeApplyPage = status != null 
			? badgeApplyRepository.findByStatusWithBasicInfo(status, pageable)
			: badgeApplyRepository.findAllWithBasicInfo(pageable);
		return BadgeApplyListResponse.from(badgeApplyPage);
	}

	@Transactional(readOnly = true)
	public BadgeApplyListResponse getAllBadgeApplies(Pageable pageable) {
		Page<BadgeApply> badgeApplyPage = badgeApplyRepository.findAllWithBasicInfo(pageable);
		return BadgeApplyListResponse.from(badgeApplyPage);
	}

	@Transactional(readOnly = true)
	public BadgeApplyListResponse getBadgeAppliesByStatus(Status status, Pageable pageable) {
		Page<BadgeApply> badgeApplyPage = badgeApplyRepository.findByStatusWithBasicInfo(status, pageable);
		return BadgeApplyListResponse.from(badgeApplyPage);
	}

	@Transactional(readOnly = true)
	public BadgeApply getBadgeApplyDetail(Long badgeApplyId) {
		return badgeApplyRepository.findByIdWithAllDetails(badgeApplyId)
			.orElseThrow(() -> new CustomException(AdminErrorCode.BADGE_APPLY_NOT_FOUND));
	}

	@Transactional
	public void approveBadgeApplication(Long badgeApplyId) {
		BadgeApply badgeApply = badgeApplyRepository.findById(badgeApplyId)
			.orElseThrow(() -> new CustomException(AdminErrorCode.BADGE_APPLY_NOT_FOUND));
		badgeApply.approveApplication();
	}
}
