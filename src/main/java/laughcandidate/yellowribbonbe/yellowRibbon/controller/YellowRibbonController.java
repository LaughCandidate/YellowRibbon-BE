package laughcandidate.yellowribbonbe.yellowRibbon.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import laughcandidate.yellowribbonbe.auth.service.CustomUserDetails;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import laughcandidate.yellowribbonbe.yellowRibbon.dto.response.YellowRibbonBenefitListResponse;
import laughcandidate.yellowribbonbe.yellowRibbon.service.YellowRibbonBenefitService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "옐로리본")
@RestController
@RequestMapping("/yellow-ribbon")
@RequiredArgsConstructor
public class YellowRibbonController {

    private final YellowRibbonBenefitService yellowRibbonBenefitService;

    @GetMapping("/benefit")
    @Operation(
            summary = "옐로 리본 혜택 조회 API",
            description = "현재 연도의 옐로 리본 혜택 목록 조회")
    public ResponseEntity<ApiResponse<YellowRibbonBenefitListResponse>> getYellowRibbonBenefits()
    {
        YellowRibbonBenefitListResponse benefits = yellowRibbonBenefitService.getBenefitsForCurrentSeason();
        return ResponseEntity.ok(ApiResponse.ok(benefits));
    }
}
