package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;

import java.util.List;

public interface YellowRibbonSuccessRepositoryCustom {
    
    Page<YellowRibbonSuccess> findAllWithBusinessInfo(Pageable pageable);

    List<YellowRibbon> findRibbonsByBusinessId(Long businessId);
}