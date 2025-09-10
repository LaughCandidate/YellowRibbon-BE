package laughcandidate.yellowribbonbe.yellowRibbon.service;

import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.BusinessErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.YellowRibbonErrorCode;
import laughcandidate.yellowribbonbe.mission.entity.Mission;
import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;
import laughcandidate.yellowribbonbe.mission.repository.MissionRepository;
import laughcandidate.yellowribbonbe.mission.repository.MissionSubmitRepository;
import laughcandidate.yellowribbonbe.image.service.ImageService;
import laughcandidate.yellowribbonbe.image.repository.ImageRepository;
import laughcandidate.yellowribbonbe.image.entity.Image;
import laughcandidate.yellowribbonbe.global.entity.Status;
import java.util.Optional;
import laughcandidate.yellowribbonbe.yellowRibbon.dto.response.RibbonSuccessListResponse;
import laughcandidate.yellowribbonbe.yellowRibbon.dto.response.YellowRibbonBenefitListResponse;
import laughcandidate.yellowribbonbe.yellowRibbon.dto.response.YellowRibbonQrPageItemResponse;
import laughcandidate.yellowribbonbe.yellowRibbon.dto.response.YellowRibbonQrPageListResponse;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonBenefit;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonBenefitRepository;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonRepository;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonSuccessRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class YellowRibbonService {
    private final MissionRepository missionRepository;
    private final MissionSubmitRepository missionSubmitRepository;
    private final ImageService imageService;
    private final ImageRepository imageRepository;
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

        if (ribbons == null || ribbons.isEmpty()) {
            throw new CustomException(YellowRibbonErrorCode.YELLOW_RIBBON_NOT_FOUND);
        }

        return RibbonSuccessListResponse.from(ribbons);
    }

    @Transactional(readOnly = true)
    public YellowRibbonQrPageListResponse getQrPage(Long businessId, Long yellowRibbonId) {

        if (businessId == null) {
            throw new CustomException(BusinessErrorCode.BUSINESS_NOT_FOUND);
        }

        Integer season = yellowRibbonRepository.findById(yellowRibbonId)
                .map(YellowRibbon::getSeason)
                .orElseThrow(() -> new CustomException(YellowRibbonErrorCode.YELLOW_RIBBON_NOT_FOUND));

        List<Mission> completedMissions = missionSubmitRepository.findCompletedMission(businessId, season);

        List<YellowRibbonQrPageItemResponse> items = new ArrayList<>();
        for (Mission mission : completedMissions) {
            MissionSubmit missionSubmit = missionSubmitRepository.findByBusinessIdWithDetails(businessId)
                    .stream()
                    .filter(ms -> ms.getMission().getId().equals(mission.getId()) && 
                                 ms.getStatus().equals(Status.COMPLETE))
                    .findFirst()
                    .orElse(null);
            
            String imageUrl = null;
            if (missionSubmit != null) {
                Optional<Image> imageOpt = imageRepository.findByMissionSubmit(missionSubmit);
                if (imageOpt.isPresent()) {
                    imageUrl = imageService.createPresignedGetUrl(imageOpt.get().getId()).presignedUrl();
                }
            }
            
            YellowRibbonQrPageItemResponse item = new YellowRibbonQrPageItemResponse(
                    mission.getBadge().getId(),
                    mission.getBadge().getCategory().toString(),
                    mission.getDescription(),
                    mission.getSuccessDescription(),
                    imageUrl
            );
            items.add(item);
        }

        return new YellowRibbonQrPageListResponse(items);
    }


}
