package laughcandidate.yellowribbonbe.yellowRibbon.service;

import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.YellowRibbonErrorCode;
import laughcandidate.yellowribbonbe.yellowRibbon.dto.response.YellowRibbonBenefitListResponse;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonBenefit;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonBenefitRepository;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class YellowRibbonBenefitService {
    private final YellowRibbonRepository yellowRibbonRepository;
    private final YellowRibbonBenefitRepository yellowRibbonBenefitRepository;

    @Transactional(readOnly = true)
    public YellowRibbonBenefitListResponse getBenefitsForCurrentSeason() {
        YellowRibbon ribbon = yellowRibbonRepository.findCurrentSeason()
                .orElseThrow(() -> new CustomException(YellowRibbonErrorCode.CURRENT_SEASON_RIBBON_NOT_FOUND));

        List<YellowRibbonBenefit> benefits = yellowRibbonBenefitRepository.findAllByYellowRibbonIdOrderByIdAsc(ribbon.getId());

        return YellowRibbonBenefitListResponse.from(benefits);
    }
}
