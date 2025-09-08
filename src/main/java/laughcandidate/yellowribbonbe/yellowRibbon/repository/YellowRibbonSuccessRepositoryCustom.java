package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;

public interface YellowRibbonSuccessRepositoryCustom {
    
    Page<YellowRibbonSuccess> findAllWithBusinessInfo(Pageable pageable);
}