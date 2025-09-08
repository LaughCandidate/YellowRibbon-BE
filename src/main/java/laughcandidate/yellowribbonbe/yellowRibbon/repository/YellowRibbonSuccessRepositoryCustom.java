package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface YellowRibbonSuccessRepositoryCustom {
    
    Page<YellowRibbonSuccess> findAllWithBusinessInfo(Pageable pageable);
}