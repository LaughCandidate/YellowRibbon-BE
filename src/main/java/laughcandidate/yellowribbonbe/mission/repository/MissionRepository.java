package laughcandidate.yellowribbonbe.mission.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import laughcandidate.yellowribbonbe.mission.entity.Mission;

public interface MissionRepository extends JpaRepository<Mission, Long> {

}
