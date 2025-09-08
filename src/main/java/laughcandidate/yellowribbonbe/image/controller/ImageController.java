package laughcandidate.yellowribbonbe.image.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import laughcandidate.yellowribbonbe.auth.service.CustomUserDetails;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import laughcandidate.yellowribbonbe.image.dto.request.GetPresignedUrlRequest;
import laughcandidate.yellowribbonbe.image.dto.request.ImageSaveRequest;
import laughcandidate.yellowribbonbe.image.dto.response.ImageSaveResponse;
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
		summary = "업로드용 Presigned Url 조회 API",
		description = "업로드용 presigned url을 조회합니다."
	)
	public ResponseEntity<ApiResponse<PresignedUrlResponse>> createPutPresignedUrl(
		@AuthenticationPrincipal CustomUserDetails customUserDetails) {

		PresignedUrlResponse result = imageService.createPresignedPutUrl();
		return ResponseEntity.ok(ApiResponse.ok(result));
	}

	@GetMapping("/get/presigned-url")
	@Operation(
		summary = "조회용 Presigned Url 조회 API",
		description = "조회용 presigned url을 조회합니다."
	)
	public ResponseEntity<ApiResponse<PresignedUrlResponse>> createGetPresignedUrl(
		@RequestBody GetPresignedUrlRequest getPresignedUrlRequest,
		@AuthenticationPrincipal CustomUserDetails customUserDetails) {

		PresignedUrlResponse result = imageService.createPresignedGetUrl(getPresignedUrlRequest.imageId());
		return ResponseEntity.ok(ApiResponse.ok(result));
	}

	@PostMapping("/upload/complete")
	@Operation(
		summary = "이미지 업로드 완료 API",
		description = "이미지 메타데이터를 저장합니다."
	)
	public ResponseEntity<ApiResponse<ImageSaveResponse>> saveImage(
		@RequestBody ImageSaveRequest imageSaveRequest,
		@AuthenticationPrincipal CustomUserDetails customUserDetails) {

		ImageSaveResponse imageSaveResponse = imageService.saveImage(imageSaveRequest.missionId(),
			imageSaveRequest.uuid(), imageSaveRequest.originalName(),
			imageSaveRequest.size(), imageSaveRequest.imageType(), customUserDetails.getBusinessId());
		return ResponseEntity.ok(ApiResponse.created(imageSaveResponse));
	}
}
