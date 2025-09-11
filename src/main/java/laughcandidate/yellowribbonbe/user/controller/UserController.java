package laughcandidate.yellowribbonbe.user.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import laughcandidate.yellowribbonbe.auth.service.CustomUserDetails;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import laughcandidate.yellowribbonbe.product.dto.ProductListResponse;
import laughcandidate.yellowribbonbe.user.dto.response.UserInfoResponse;
import laughcandidate.yellowribbonbe.user.service.UserService;
import lombok.RequiredArgsConstructor;

@Tag(name = "유저")
@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;

	@GetMapping
	@Operation(
		summary = "유저 정보 조회 API",
		description = "유저 정보를 조회합니다.")
	public ResponseEntity<ApiResponse<UserInfoResponse>> getUserInfo(
		@AuthenticationPrincipal CustomUserDetails customUserDetails) {

		UserInfoResponse userInfo = userService.getUserInfo(customUserDetails.getUid());
		return ResponseEntity.ok(ApiResponse.ok(userInfo));
	}
}
