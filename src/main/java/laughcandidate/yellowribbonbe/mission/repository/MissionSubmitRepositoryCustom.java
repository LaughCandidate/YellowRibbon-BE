package laughcandidate.yellowribbonbe.mission.repository;

import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;

import java.util.List;

public interface MissionSubmitRepositoryCustom {
    
    List<MissionSubmit> findByBusinessIdWithDetails(Long businessId);
}