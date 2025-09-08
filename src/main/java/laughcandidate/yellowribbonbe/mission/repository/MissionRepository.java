package laughcandidate.yellowribbonbe.mission.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import laughcandidate.yellowribbonbe.mission.entity.Mission;
import laughcandidate.yellowribbonbe.mission.repository.custom.MissionCustomRepository;

public interface MissionRepository extends JpaRepository<Mission, Long>, MissionCustomRepository {

}
