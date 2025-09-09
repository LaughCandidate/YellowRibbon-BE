package laughcandidate.yellowribbonbe.badge.repository;

import laughcandidate.yellowribbonbe.badge.entity.Badge;

import java.util.List;

public interface BadgeRepositoryCustom {
    
    List<Badge> findAllWithMissions();
}