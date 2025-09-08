package laughcandidate.yellowribbonbe.badge.service;

import laughcandidate.yellowribbonbe.badge.dto.response.BadgeApplyResponse;
import laughcandidate.yellowribbonbe.badge.dto.response.BadgeInfoListResponse;
import laughcandidate.yellowribbonbe.badge.dto.response.BadgeInfoResponse;
import laughcandidate.yellowribbonbe.badge.dto.response.BadgeIssuanceResponse;
import laughcandidate.yellowribbonbe.badge.entity.Badge;
import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.badge.repository.BadgeApplyRepository;
import laughcandidate.yellowribbonbe.badge.repository.BadgeRepository;
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

    @Transactional(readOnly = true)
    public BadgeInfoListResponse getBadgesInfo(Long userId, Long businessId){

        if (businessId == null) {
            throw new IllegalArgumentException("businessId는 필수입니다.");
        }

        List<Badge> badges = badgeRepository.findAll();

        List<BadgeApply> applies =
                badgeApplyRepository.findByUserIdAndBusinessId(userId, businessId);

        Map<Long, BadgeApply> applyMap = applies.stream()
                .collect(Collectors.toMap(a -> a.getBadge().getId(), Function.identity()));

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

    public BadgeIssuanceResponse applyBadge(Long userId, Long businessId, Long badgeId){

    }

}
