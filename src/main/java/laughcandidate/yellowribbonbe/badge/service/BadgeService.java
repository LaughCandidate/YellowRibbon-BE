package laughcandidate.yellowribbonbe.badge.service;

import laughcandidate.yellowribbonbe.badge.dto.response.BadgeApplyResponse;
import laughcandidate.yellowribbonbe.badge.dto.response.BadgeInfoListResponse;
import laughcandidate.yellowribbonbe.badge.dto.response.BadgeInfoResponse;
import laughcandidate.yellowribbonbe.badge.dto.response.BadgeIssuanceResponse;
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
import laughcandidate.yellowribbonbe.user.entity.User;
import laughcandidate.yellowribbonbe.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class BadgeService {

    private final BadgeRepository badgeRepository;
    private final BadgeApplyRepository badgeApplyRepository;
    private final UserRepository userRepository;
    private final BusinessRepository businessRepository;

    @Transactional(readOnly = true)
    public BadgeInfoListResponse getBadgesInfo(Long userId, Long businessId){

        if (userId == null || businessId == null) {
            throw new CustomException(CommonErrorCode.MISSING_PARAMETER);
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(AuthErrorCode.USER_NOT_FOUND));

        Business business = businessRepository.findById(businessId)
                .orElseThrow(() -> new CustomException(BusinessErrorCode.BUSINESS_NOT_FOUND));

        // 사업자 - 사용자 매칭 검증
        if (business.getUser() == null || !business.getUser().getId().equals(user.getId())) {
            throw new CustomException(AuthErrorCode.ACCESS_DENIED);
        }

        List<Badge> badges = badgeRepository.findAll();

        List<BadgeApply> applies =
                badgeApplyRepository.findByUserIdAndBusinessId(userId, businessId);

        Map<Long, BadgeApply> applyMap = applies.stream()
                .sorted(Comparator.comparing(BadgeApply::getCreatedAt).reversed())
                .collect(Collectors.toMap(
                        a -> a.getBadge().getId(),
                        Function.identity(),
                        (existing, ignored) -> existing
                ));

        List<BadgeInfoResponse> responses = badges.stream()
                .sorted(Comparator.comparing((Badge b) -> b.getCategory() == null ? "" : b.getCategory().getCategory())
                        .thenComparing(Badge::getId))
                .map(badge -> {
                    BadgeApply apply = applyMap.get(badge.getId());
                    return new BadgeInfoResponse(
                            badge.getId(),
                            badge.getCategory() == null ? null : badge.getCategory().getCategory(),
                            (apply == null)
                                    ? null
                                    : new BadgeApplyResponse(apply.getId(), apply.getStatus().name())
                    );
                })
                .toList();

        return new BadgeInfoListResponse(responses);
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
