package laughcandidate.yellowribbonbe.image.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import laughcandidate.yellowribbonbe.auth.service.CustomUserDetails;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import laughcandidate.yellowribbonbe.image.dto.response.PresignedUrlResponse;
import laughcandidate.yellowribbonbe.image.service.ImageService;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/image")
@RequiredArgsConstructor
public class ImageController {

	private final ImageService imageService;

	@GetMapping("/put/presigned-url")
	@Operation(
		summary = "Presigned Url 조회 API",
		description = "presigned url을 조회합니다."
	)
	public ResponseEntity<ApiResponse<PresignedUrlResponse>> createPresignedUrl(
		@AuthenticationPrincipal CustomUserDetails customUserDetails) {

		PresignedUrlResponse result = imageService.createPresignedPutUrl();
		return ResponseEntity.ok(ApiResponse.ok(result));
	}
}
