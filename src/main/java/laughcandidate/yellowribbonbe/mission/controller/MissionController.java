package laughcandidate.yellowribbonbe.mission.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import laughcandidate.yellowribbonbe.mission.dto.request.MissionValidationRequest;
import laughcandidate.yellowribbonbe.mission.dto.response.MissionValidationResponse;
import laughcandidate.yellowribbonbe.mission.service.MissionService;
import lombok.RequiredArgsConstructor;

@Tag(name = "미션")
@RestController
@RequestMapping("/mission")
@RequiredArgsConstructor
public class MissionController {

	private final MissionService missionService;

	@PostMapping("/{missionId}/validate")
	@Operation(
		summary = "미션 검증 API",
		description = "업로드된 이미지가 미션을 완료했는지 AI로 검증합니다."
	)
	public ResponseEntity<ApiResponse<MissionValidationResponse>> validateMission(
		@PathVariable Long missionId,
		@Valid @ModelAttribute MissionValidationRequest request) {

		MissionValidationResponse result = missionService.validateMission(missionId, request.image());
		return ResponseEntity.ok(ApiResponse.ok(result));
	}
}