package laughcandidate.yellowribbonbe.mission.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;
import laughcandidate.yellowribbonbe.mission.repository.custom.MissionCustomRepository;

public interface MissionSubmitRepository extends JpaRepository<MissionSubmit, Long>, MissionCustomRepository {
}
