package laughcandidate.yellowribbonbe.yellowRibbon.service;

import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.BusinessErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.YellowRibbonErrorCode;
import laughcandidate.yellowribbonbe.yellowRibbon.dto.response.RibbonSuccessListResponse;
import laughcandidate.yellowribbonbe.yellowRibbon.dto.response.YellowRibbonBenefitListResponse;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonBenefit;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonBenefitRepository;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonRepository;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonSuccessRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class YellowRibbonService {
    private final YellowRibbonRepository yellowRibbonRepository;
    private final YellowRibbonBenefitRepository yellowRibbonBenefitRepository;
    private final YellowRibbonSuccessRepository yellowRibbonSuccessRepository;

    @Transactional(readOnly = true)
    public YellowRibbonBenefitListResponse getBenefitsForCurrentSeason() {
        YellowRibbon ribbon = yellowRibbonRepository.findCurrentSeason()
                .orElseThrow(() -> new CustomException(YellowRibbonErrorCode.CURRENT_SEASON_RIBBON_NOT_FOUND));

        List<YellowRibbonBenefit> benefits = yellowRibbonBenefitRepository.findAllByYellowRibbonIdOrderByIdAsc(ribbon.getId());

        return YellowRibbonBenefitListResponse.from(benefits);
    }

    @Transactional(readOnly = true)
    public RibbonSuccessListResponse getRibbonSuccesses(Long businessId) {
        if (businessId == null) {
            throw new CustomException(BusinessErrorCode.BUSINESS_NOT_FOUND);
        }

        List<YellowRibbon> ribbons =
                yellowRibbonSuccessRepository.findRibbonsByBusinessId(businessId);

        if (ribbons.isEmpty()) {
            return RibbonSuccessListResponse.empty("현재 사업장에서 보유한 옐로 리본이 없습니다.");
        }

        return RibbonSuccessListResponse.from(ribbons);
    }
}
