package laughcandidate.yellowribbonbe.badge.repository;

import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.badge.entity.Status;

public interface BadgeApplyRepository extends JpaRepository<BadgeApply, Long> {

	@Query("SELECT DISTINCT ba FROM BadgeApply ba " +
		"JOIN FETCH ba.user u " +
		"JOIN FETCH ba.badge b " +
		"JOIN FETCH ba.business bus " +
		"ORDER BY ba.createdAt DESC ")
	Page<BadgeApply> findAllWithBasicInfo(Pageable pageable);

	@Query("SELECT DISTINCT ba FROM BadgeApply ba " +
		"JOIN FETCH ba.user u " +
		"JOIN FETCH ba.badge b " +
		"JOIN FETCH ba.business bus " +
		"WHERE ba.status = :status " +
		"ORDER BY ba.createdAt DESC")
	Page<BadgeApply> findByStatusWithBasicInfo(@Param("status") Status status, Pageable pageable);

	@Query("SELECT ba FROM BadgeApply ba " +
		"JOIN FETCH ba.user u " +
		"JOIN FETCH ba.badge b " +
		"JOIN FETCH ba.business bus " +
		"WHERE ba.id = :id")
	Optional<BadgeApply> findByIdWithAllDetails(@Param("id") Long id);
}
