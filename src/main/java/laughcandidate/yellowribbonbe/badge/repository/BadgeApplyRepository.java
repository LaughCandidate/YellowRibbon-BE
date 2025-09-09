package laughcandidate.yellowribbonbe.badge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;

import java.util.Optional;

public interface BadgeApplyRepository extends JpaRepository<BadgeApply, Long>, BadgeApplyRepositoryCustom {
    Optional<BadgeApply> findByBusinessIdAndBadgeId(Long businessId, Long badgeId);
}