package laughcandidate.yellowribbonbe.admin.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import laughcandidate.yellowribbonbe.admin.dto.response.RibbonIssueListResponse;
import laughcandidate.yellowribbonbe.admin.service.AdminRibbonService;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "관리자 - 리본 발급 내역 관리")
@RestController
@RequestMapping("/admin/ribbon")
@RequiredArgsConstructor
public class AdminRibbonController {

    private final AdminRibbonService adminRibbonService;

    @GetMapping("/list")
    @Operation(
            summary = "리본 발급 내역 조회 API",
            description = "관리자용 리본 발급 내역을 페이지네이션으로 조회합니다.")
    public ResponseEntity<ApiResponse<RibbonIssueListResponse>> getRibbonIssues(
            @Parameter(description = "페이지 정보 (page, size, sort)")
            @PageableDefault(size = 20, sort = "createdAt") Pageable pageable) {

        RibbonIssueListResponse response = adminRibbonService.getAllRibbonIssues(pageable);
        return ResponseEntity.ok(ApiResponse.ok(response));
    }
}