package laughcandidate.yellowribbonbe.business.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import laughcandidate.yellowribbonbe.business.entity.Business;

public interface BusinessRepository extends JpaRepository<Business, Long> {

	boolean existsByBusinessNo(String businessNo);
}
