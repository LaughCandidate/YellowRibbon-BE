package laughcandidate.yellowribbonbe.mission.repository.custom;

import laughcandidate.yellowribbonbe.mission.dto.response.MissionInfoDto;
import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;

import java.util.List;

public interface MissionCustomRepository {
    
    List<MissionInfoDto> findMissionWithSubmitData(Long badgeId, Long businessId);

    List<MissionSubmit> findByBusinessIdWithDetails(Long businessId);

}