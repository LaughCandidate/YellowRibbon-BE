package laughcandidate.yellowribbonbe.image.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import laughcandidate.yellowribbonbe.image.entity.Image;
import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;

import java.util.Optional;

public interface ImageRepository extends JpaRepository<Image, Long> {
    
    Optional<Image> findByMissionSubmit(MissionSubmit missionSubmit);
}
