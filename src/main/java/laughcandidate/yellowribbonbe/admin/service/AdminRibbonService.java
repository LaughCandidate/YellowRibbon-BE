package laughcandidate.yellowribbonbe.admin.service;

import laughcandidate.yellowribbonbe.admin.dto.response.RibbonIssueListResponse;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonSuccessRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AdminRibbonService {

    private final YellowRibbonSuccessRepository yellowRibbonSuccessRepository;

    @Transactional(readOnly = true)
    public RibbonIssueListResponse getAllRibbonIssues(Pageable pageable) {
        Page<YellowRibbonSuccess> ribbonSuccessPage = yellowRibbonSuccessRepository.findAllWithBusinessInfo(pageable);
        return RibbonIssueListResponse.from(ribbonSuccessPage);
    }
}