package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonBenefit;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface YellowRibbonBenefitRepository extends JpaRepository<YellowRibbonBenefit, Long> {
    List<YellowRibbonBenefit> findAllByYellowRibbonIdOrderByIdAsc(Long yellowRibbonId);
}
