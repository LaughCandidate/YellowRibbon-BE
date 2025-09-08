package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import org.springframework.data.jpa.repository.JpaRepository;

public interface YellowRibbonRepository extends JpaRepository<YellowRibbon, Long>, YellowRibbonRepositoryCustom {
}