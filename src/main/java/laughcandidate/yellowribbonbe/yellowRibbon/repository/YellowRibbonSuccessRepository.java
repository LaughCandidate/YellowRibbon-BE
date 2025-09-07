package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface YellowRibbonSuccessRepository extends JpaRepository<YellowRibbonSuccess, Long> {

    @Query("SELECT yrs FROM YellowRibbonSuccess yrs " +
           "JOIN FETCH yrs.business b " +
           "ORDER BY yrs.createdAt DESC")
    Page<YellowRibbonSuccess> findAllWithBusinessInfo(Pageable pageable);
}