package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import org.springframework.data.jpa.repository.JpaRepository;

public interface YellowRibbonSuccessRepository extends JpaRepository<YellowRibbonSuccess, Long>, YellowRibbonSuccessRepositoryCustom {
}