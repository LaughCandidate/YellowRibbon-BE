package laughcandidate.yellowribbonbe.business.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import laughcandidate.yellowribbonbe.auth.service.CustomUserDetails;
import laughcandidate.yellowribbonbe.business.dto.request.ConnectOptionalRequest;
import laughcandidate.yellowribbonbe.business.dto.request.ConnectRequiredRequest;
import laughcandidate.yellowribbonbe.business.dto.response.BusinessInfoResponse;
import laughcandidate.yellowribbonbe.business.dto.response.BusinessInfoListResponse;
import laughcandidate.yellowribbonbe.business.dto.response.ConnectResponse;
import laughcandidate.yellowribbonbe.business.service.BusinessService;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import lombok.RequiredArgsConstructor;

@Tag(name = "사업자")
@RestController
@RequestMapping("/business")
@RequiredArgsConstructor
public class BusinessController {

	private final BusinessService businessService;

	@PostMapping("/connect/required")
	@Operation(
		summary = "사업자 연동 API",
		description = "사업장 연동")
	public ResponseEntity<ApiResponse<ConnectResponse>> connectBusinessRequired(
		@RequestBody @Valid ConnectRequiredRequest connectRequiredRequest,
		@AuthenticationPrincipal
		CustomUserDetails customUserDetails) {

		ConnectResponse connectResponse = businessService.connectBusinessRequired(connectRequiredRequest.businessNo(),
			connectRequiredRequest.ownerName(),
			connectRequiredRequest.startDate(), connectRequiredRequest.businessName(), connectRequiredRequest.isLast(),
			customUserDetails.getUserId());
		return ResponseEntity.ok(ApiResponse.created(connectResponse));
	}

	@PostMapping("/connect/optional")
	@Operation(
		summary = "사업자 연동 API",
		description = "사업장 연동")
	public ResponseEntity<ApiResponse<Void>> connectBusinessOptional(
		@RequestBody @Valid ConnectOptionalRequest connectOptionalRequest,
		@AuthenticationPrincipal
		CustomUserDetails customUserDetails) {

		businessService.connectBusinessOptional(connectOptionalRequest.businessNo(), connectOptionalRequest.ownerName(),
			connectOptionalRequest.startDate(), connectOptionalRequest.businessName(), customUserDetails.getUserId());
		return ResponseEntity.ok(ApiResponse.noContent());
	}

	@GetMapping("/info")
	@Operation(
		summary = "내 사업자 조회 API",
		description = "현재 사용자의 사업자 목록 조회")
	public ResponseEntity<ApiResponse<BusinessInfoListResponse>> getBusinessesInfo(
		@AuthenticationPrincipal CustomUserDetails customUserDetails) {

		BusinessInfoListResponse businessesInfo = businessService.getBusinessesInfo(customUserDetails.getUserId());
		return ResponseEntity.ok(ApiResponse.ok(businessesInfo));
	}
}
