package laughcandidate.yellowribbonbe.admin.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import laughcandidate.yellowribbonbe.admin.dto.request.MissionStatusUpdateRequest;
import laughcandidate.yellowribbonbe.admin.service.AdminMissionService;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import lombok.RequiredArgsConstructor;

@Tag(name = "관리자 - 미션 관리")
@RestController
@RequestMapping("/admin/mission")
@RequiredArgsConstructor
public class AdminMissionController {

    private final AdminMissionService adminMissionService;

    @PatchMapping("/{missionSubmitId}/status")
    @Operation(
        summary = "미션 상태 변경 API",
        description = "관리자가 미션 제출의 상태를 변경합니다. ")
    public ResponseEntity<ApiResponse<Void>> updateMissionStatus(
        @Parameter(description = "미션 제출 ID")
        @PathVariable Long missionSubmitId,
        
        @Parameter(description = "상태 변경 요청 정보")
        @Valid @RequestBody MissionStatusUpdateRequest request
    ) {
        adminMissionService.updateMissionStatus(missionSubmitId, request);
        return ResponseEntity.ok(ApiResponse.ok(null));
    }
}