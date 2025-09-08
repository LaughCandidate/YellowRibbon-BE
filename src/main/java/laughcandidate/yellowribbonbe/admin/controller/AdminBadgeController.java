package laughcandidate.yellowribbonbe.admin.controller;

import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import laughcandidate.yellowribbonbe.admin.dto.response.BadgeApplyListResponse;
import laughcandidate.yellowribbonbe.admin.dto.response.BadgeApplyListItemResponse;
import laughcandidate.yellowribbonbe.admin.service.AdminBadgeService;
import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.global.entity.Status;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import lombok.RequiredArgsConstructor;

@Tag(name = "관리자 - 배지 신청 관리")
@RestController
@RequestMapping("/admin/badge")
@RequiredArgsConstructor
public class AdminBadgeController {

	private final AdminBadgeService adminBadgeService;

	@GetMapping("/list")
	@Operation(
		summary = "배지 신청 목록 조회 API",
		description = "관리자용 배지 신청 목록을 페이지네이션으로 조회합니다. 상태별 필터링 지원")
	public ResponseEntity<ApiResponse<BadgeApplyListResponse>> getBadgeApplies(
		@Parameter(description = "필터링할 상태 (PENDING, COMPLETE, REJECTED)")
		@RequestParam(required = false) Status status,
		@Parameter(description = "페이지 정보 (page, size, sort)")
		@PageableDefault(size = 20, sort = "createdAt") Pageable pageable) {

		BadgeApplyListResponse response = adminBadgeService.getBadgeApplies(status, pageable);
		return ResponseEntity.ok(ApiResponse.ok(response));
	}

	@GetMapping("/{badgeApplyId}")
	@Operation(
		summary = "배지 신청 상세 조회 API",
		description = "특정 배지 신청의 상세 정보를 조회합니다.")
	public ResponseEntity<ApiResponse<BadgeApplyListItemResponse>> getBadgeApplyDetail(
		@Parameter(description = "배지 신청 ID")
		@PathVariable Long badgeApplyId
	) {
		BadgeApply badgeApply = adminBadgeService.getBadgeApplyDetail(badgeApplyId);
		BadgeApplyListItemResponse response = BadgeApplyListItemResponse.from(badgeApply);
		return ResponseEntity.ok(ApiResponse.ok(response));
	}

	@PostMapping("/{badgeApplyId}/approve")
	@Operation(
		summary = "배지 신청 승인 API",
		description = "배지 신청을 승인하여 배지를 발급합니다.")
	public ResponseEntity<ApiResponse<Void>> approveBadgeApplication(
		@Parameter(description = "배지 신청 ID")
		@PathVariable Long badgeApplyId
	) {
		adminBadgeService.approveBadgeApplication(badgeApplyId);
		return ResponseEntity.ok(ApiResponse.ok(null));
	}
}