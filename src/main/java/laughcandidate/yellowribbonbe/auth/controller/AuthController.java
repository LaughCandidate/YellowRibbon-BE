package laughcandidate.yellowribbonbe.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import laughcandidate.yellowribbonbe.auth.dto.request.PhoneCheckRequest;
import laughcandidate.yellowribbonbe.auth.dto.request.PhoneVerificationRequest;
import laughcandidate.yellowribbonbe.auth.dto.response.PhoneVerificationResultResponse;
import laughcandidate.yellowribbonbe.auth.service.AuthService;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import lombok.RequiredArgsConstructor;

@Tag(name = "인증/인가")
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

	private final AuthService authService;

	@PostMapping("/check-phone")
	@Operation(
		summary = "전화번호 중복 확인 API",
		description = "전화번호 중복 확인")
	public ResponseEntity<ApiResponse<Void>> checkIdDuplicate(@RequestBody @Valid PhoneCheckRequest phoneCheckRequest) {
		authService.checkPhoneDuplicate(phoneCheckRequest.phone());

		return ResponseEntity.ok(ApiResponse.noContent());
	}

	@PostMapping("/send-code")
	@Operation(
		summary = "인증번호 요청 API",
		description = "인증번호 요청")
	public ResponseEntity<ApiResponse<PhoneVerificationResultResponse>> sendVerificationCode(@RequestBody @Valid PhoneVerificationRequest phoneVerificationRequest) {
		PhoneVerificationResultResponse phoneVerificationResultResponse = authService.sendVerificationCode(
			phoneVerificationRequest.phone());

		return ResponseEntity.ok(ApiResponse.created(phoneVerificationResultResponse));
	}

	@PostMapping("/verify-code")
	@Operation(
		summary = "인증번호 검증 API",
		description = "인증번호 검증")
	public ResponseEntity<ApiResponse<Void>> verify(@RequestBody @Valid PhoneVerificationRequest phoneVerificationRequest) {
		authService.verifyCode(phoneVerificationRequest.phone());

		return ResponseEntity.ok(ApiResponse.noContent());
	}
}
