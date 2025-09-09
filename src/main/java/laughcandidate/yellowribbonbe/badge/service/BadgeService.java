package laughcandidate.yellowribbonbe.badge.service;

import laughcandidate.yellowribbonbe.badge.dto.response.BadgeApplyResponse;
import laughcandidate.yellowribbonbe.badge.dto.response.BadgeInfoListResponse;
import laughcandidate.yellowribbonbe.badge.dto.response.BadgeInfoResponse;
import laughcandidate.yellowribbonbe.badge.dto.response.BadgeIssuanceResponse;
import laughcandidate.yellowribbonbe.badge.dto.response.SummaryBadgeInfoResponse;
import laughcandidate.yellowribbonbe.badge.entity.Badge;
import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.badge.repository.BadgeApplyRepository;
import laughcandidate.yellowribbonbe.badge.repository.BadgeRepository;
import laughcandidate.yellowribbonbe.business.entity.Business;
import laughcandidate.yellowribbonbe.business.repository.BusinessRepository;
import laughcandidate.yellowribbonbe.global.entity.Status;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AuthErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.BadgeErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.BusinessErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.CommonErrorCode;
import laughcandidate.yellowribbonbe.mission.entity.Mission;
import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;
import laughcandidate.yellowribbonbe.mission.repository.MissionSubmitRepository;
import laughcandidate.yellowribbonbe.user.entity.User;
import laughcandidate.yellowribbonbe.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class BadgeService {

    private final BadgeRepository badgeRepository;
    private final BadgeApplyRepository badgeApplyRepository;
    private final UserRepository userRepository;
    private final BusinessRepository businessRepository;
    private final MissionSubmitRepository missionSubmitRepository;

    @Transactional(readOnly = true)
    public BadgeInfoListResponse getBadgesInfo(Long businessId){
        List<Badge> badges = badgeRepository.findAllWithMissions();
        
        List<BadgeInfoResponse> badgeInfoResponses = new ArrayList<>();
        long totalSummaryMissionCount = 0;
        long successMissionSummaryCount = 0;
        
        for (Badge badge : badges) {
            List<Mission> missions = badge.getMissions();
            
            long totalMissionCount = missions.size();
            
            long successMissionCount = 0;
            for (Mission mission : missions) {
                List<MissionSubmit> allSubmits = missionSubmitRepository.findAll();
                for (MissionSubmit submit : allSubmits) {
                    if (submit.getMission().getId().equals(mission.getId()) 
                            && submit.getBusiness().getId().equals(businessId)
                            && submit.getStatus() == Status.COMPLETE) {
                        successMissionCount++;
                    }
                }
            }
            
            Status badgeStatus = null;
            BadgeApply badgeApply = badgeApplyRepository.findByBusinessIdAndBadgeId(businessId, badge.getId()).orElse(null);
            if (badgeApply != null) {
                badgeStatus = badgeApply.getStatus();
            }
            
            BadgeInfoResponse response = new BadgeInfoResponse(
                    badge.getId(),
                    badge.getCategory(),
                    totalMissionCount,
                    successMissionCount,
                    badgeStatus
            );
            badgeInfoResponses.add(response);
            
            totalSummaryMissionCount += totalMissionCount;
            successMissionSummaryCount += successMissionCount;
        }
        
        SummaryBadgeInfoResponse summaryResponse = new SummaryBadgeInfoResponse(
                totalSummaryMissionCount,
                successMissionSummaryCount
        );

        return new BadgeInfoListResponse(badgeInfoResponses, summaryResponse);
    }

    @Transactional
    public BadgeIssuanceResponse applyBadge(Long userId, Long businessId, Long badgeId){

        if (userId == null || businessId == null || badgeId == null) {
            throw new CustomException(CommonErrorCode.MISSING_PARAMETER);
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(AuthErrorCode.USER_NOT_FOUND));
        Business business = businessRepository.findById(businessId)
                .orElseThrow(() -> new CustomException(BusinessErrorCode.BUSINESS_NOT_FOUND));
        Badge badge = badgeRepository.findById(badgeId)
                .orElseThrow(() -> new CustomException(BadgeErrorCode.BADGE_NOT_FOUND));


        BadgeApply entity = BadgeApply.builder()
                .user(user)
                .business(business)
                .badge(badge)
                .status(Status.PENDING)
                .build();

        BadgeApply saved = badgeApplyRepository.save(entity);

        return new BadgeIssuanceResponse(
                saved.getId(),
                businessId,
                badgeId,
                saved.getStatus().name()
        );
    }
}
