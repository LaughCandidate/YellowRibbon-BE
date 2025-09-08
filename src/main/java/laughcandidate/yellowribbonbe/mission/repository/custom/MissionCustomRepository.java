package laughcandidate.yellowribbonbe.mission.repository.custom;

import laughcandidate.yellowribbonbe.mission.dto.response.MissionInfoDto;
import java.util.List;

public interface MissionCustomRepository {
    
    List<MissionInfoDto> findMissionWithSubmitData(Long badgeId, Long businessId);
}