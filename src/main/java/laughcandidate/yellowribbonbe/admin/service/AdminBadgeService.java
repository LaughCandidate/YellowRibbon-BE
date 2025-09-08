package laughcandidate.yellowribbonbe.admin.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import laughcandidate.yellowribbonbe.admin.dto.response.BadgeApplyListResponse;
import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.global.entity.Status;
import laughcandidate.yellowribbonbe.badge.repository.BadgeApplyRepository;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AdminErrorCode;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonRepository;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonSuccessRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AdminBadgeService {

	private final BadgeApplyRepository badgeApplyRepository;
	private final YellowRibbonRepository yellowRibbonRepository;
	private final YellowRibbonSuccessRepository yellowRibbonSuccessRepository;
	
	private static final int REQUIRED_BADGES_FOR_RIBBON = 5;

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
		
		long completedBadgeCount = badgeApplyRepository.countByUserIdAndStatus(
			badgeApply.getUser().getId(), Status.COMPLETE);
		
		if (completedBadgeCount == REQUIRED_BADGES_FOR_RIBBON) {
			issueRibbon(badgeApply);
		}
	}
	
	private void issueRibbon(BadgeApply badgeApply) {
		YellowRibbon currentRibbon = yellowRibbonRepository.findCurrentSeason()
			.orElseThrow(() -> new CustomException(AdminErrorCode.YELLOW_RIBBON_NOT_FOUND));
		
		YellowRibbonSuccess ribbonSuccess = YellowRibbonSuccess.builder()
			.user(badgeApply.getUser())
			.business(badgeApply.getBusiness())
			.yellowRibbon(currentRibbon)
			.build();
		
		yellowRibbonSuccessRepository.save(ribbonSuccess);
	}
}