package laughcandidate.yellowribbonbe.badge.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import laughcandidate.yellowribbonbe.auth.service.CustomUserDetails;
import laughcandidate.yellowribbonbe.badge.dto.request.BadgeIssuanceRequest;
import laughcandidate.yellowribbonbe.badge.dto.response.BadgeInfoListResponse;
import laughcandidate.yellowribbonbe.badge.dto.response.BadgeIssuanceResponse;
import laughcandidate.yellowribbonbe.badge.service.BadgeService;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@Tag(name = "배지")
@RestController
@RequestMapping("/badge")
@RequiredArgsConstructor
public class BadgeController {

    private final BadgeService badgeService;

    @GetMapping("/info")
    @Operation(
            summary = "전체 배지 목록 조회 API",
            description = "현재 사업장의 배지 목록 조회")
    public ResponseEntity<ApiResponse<BadgeInfoListResponse>> getBadgesInfo(
            @AuthenticationPrincipal CustomUserDetails customUserDetails
    ) {
        BadgeInfoListResponse badgesInfo = badgeService.getBadgesInfo(customUserDetails.getUserId(), customUserDetails.getBusinessId());

        return ResponseEntity.ok(ApiResponse.ok(badgesInfo));
    }

    @PostMapping("/application")
    @Operation(
            summary = "배지 발급 신청 API",
            description = "배지 발급 신청")
    public ResponseEntity<ApiResponse<BadgeIssuanceResponse>> applyBadge(
            @RequestBody BadgeIssuanceRequest request,
            @AuthenticationPrincipal CustomUserDetails customUserDetails
    ) {
        BadgeIssuanceResponse result = badgeService.applyBadge(customUserDetails.getUserId(), customUserDetails.getBusinessId(), request.badgeId());

        return ResponseEntity.ok(ApiResponse.ok(result));
    }

}


