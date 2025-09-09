package laughcandidate.yellowribbonbe.admin.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import laughcandidate.yellowribbonbe.admin.dto.response.BadgeApplyListResponse;
import laughcandidate.yellowribbonbe.admin.dto.response.BadgeApplyListItemResponse;
import laughcandidate.yellowribbonbe.admin.dto.response.MissionSubmitResponse;
import laughcandidate.yellowribbonbe.mission.dto.response.MissionListResponse;
import laughcandidate.yellowribbonbe.mission.service.MissionService;
import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.global.entity.Status;
import laughcandidate.yellowribbonbe.badge.repository.BadgeApplyRepository;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AdminErrorCode;
import laughcandidate.yellowribbonbe.image.service.ImageService;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonRepository;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonSuccessRepository;
import lombok.RequiredArgsConstructor;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminBadgeService {

	private final BadgeApplyRepository badgeApplyRepository;
	private final YellowRibbonRepository yellowRibbonRepository;
	private final YellowRibbonSuccessRepository yellowRibbonSuccessRepository;
	private final MissionService missionService;
	private final ImageService imageService;
	
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

	@Transactional(readOnly = true)
	public BadgeApplyListItemResponse getBadgeApplyDetailWithMissions(Long badgeApplyId) {
		BadgeApply badgeApply = badgeApplyRepository.findByIdWithAllDetails(badgeApplyId)
			.orElseThrow(() -> new CustomException(AdminErrorCode.BADGE_APPLY_NOT_FOUND));
		
		MissionListResponse missionListResponse = missionService.getMissionList(
			badgeApply.getBadge().getId(),
			badgeApply.getBusiness().getId()
		);
		
		List<MissionSubmitResponse> missionSubmitResponses = missionListResponse.missions().stream()
			.filter(mission -> mission.tried() && mission.missionSubmitId() != null)
			.map(mission -> {
				String imageUrl = null;
				
				if (mission.imageId() != null) {
					try {
						imageUrl = imageService.createPresignedGetUrl(mission.imageId()).presignedUrl();
					} catch (Exception e) {
						imageUrl = null;
					}
				}
				
				return MissionSubmitResponse.builder()
					.missionSubmitId(mission.missionSubmitId())
					.status(mission.status())
					.reason(mission.reason())
					.missionCategory(mission.category().name())
					.missionDescription(mission.description())
					.imageUrl(imageUrl)
					.submittedAt(mission.submittedAt())
					.build();
			})
			.toList();
		
		return BadgeApplyListItemResponse.from(badgeApply, missionSubmitResponses);
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