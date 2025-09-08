package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;

import java.util.Optional;

public interface YellowRibbonRepositoryCustom {
    
    Optional<YellowRibbon> findCurrentSeason();
}