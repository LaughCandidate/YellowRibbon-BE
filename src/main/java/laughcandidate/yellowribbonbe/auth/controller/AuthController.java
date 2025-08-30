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
}
