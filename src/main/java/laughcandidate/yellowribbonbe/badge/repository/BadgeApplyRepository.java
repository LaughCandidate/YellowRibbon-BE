package laughcandidate.yellowribbonbe.badge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;

public interface BadgeApplyRepository extends JpaRepository<BadgeApply, Long>, BadgeApplyRepositoryCustom {
}
