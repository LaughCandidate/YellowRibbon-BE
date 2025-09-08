package laughcandidate.yellowribbonbe.badge.repository;

import laughcandidate.yellowribbonbe.badge.entity.Badge;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BadgeRepository extends JpaRepository<Badge, Long> {
}
