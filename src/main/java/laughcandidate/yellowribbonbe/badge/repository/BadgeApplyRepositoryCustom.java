package laughcandidate.yellowribbonbe.badge.repository;

import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.global.entity.Status;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Optional;

public interface BadgeApplyRepositoryCustom {
    
    Page<BadgeApply> findAllWithBasicInfo(Pageable pageable);
    
    Page<BadgeApply> findByStatusWithBasicInfo(Status status, Pageable pageable);
    
    Optional<BadgeApply> findByIdWithAllDetails(Long badgeApplyId);
    
    long countByUserIdAndStatus(Long userId, Status status);
}