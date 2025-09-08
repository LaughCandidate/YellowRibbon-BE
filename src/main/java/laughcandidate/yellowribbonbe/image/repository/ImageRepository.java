package laughcandidate.yellowribbonbe.image.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import laughcandidate.yellowribbonbe.image.entity.Image;

public interface ImageRepository extends JpaRepository<Image, Long> {
}
