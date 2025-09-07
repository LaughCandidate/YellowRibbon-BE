package laughcandidate.yellowribbonbe.admin.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import laughcandidate.yellowribbonbe.admin.dto.response.BadgeApplyListItemResponse;
import laughcandidate.yellowribbonbe.admin.dto.response.BadgeApplyListResponse;
import laughcandidate.yellowribbonbe.admin.service.AdminBadgeService;
import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.badge.entity.Category;
import laughcandidate.yellowribbonbe.badge.entity.Status;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AdminErrorCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Pageable;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ActiveProfiles("test")
@WebMvcTest(AdminBadgeController.class)
class AdminBadgeControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private ObjectMapper objectMapper;

	@MockBean
	private AdminBadgeService adminBadgeService;

	@Test
	@WithMockUser(authorities = "ROLE_ADMIN")
	@DisplayName("관리자는 모든 배지 신청 목록을 조회할 수 있다")
	void getAllBadgeApplies() throws Exception {
		// given
		BadgeApplyListItemResponse item = BadgeApplyListItemResponse.builder()
			.badgeApplyId(1L)
			.status(Status.PENDING)
			.applicantName("홍길동")
			.applicantPhone("010-1234-5678")
			.businessName("테스트 카페")
			.businessNo("123-45-67890")
			.badgeCategory(Category.ENVIRONMENT_PROTECTION)
			.appliedAt(LocalDateTime.now())
			.build();

		BadgeApplyListResponse response = BadgeApplyListResponse.builder()
			.badgeApplies(List.of(item))
			.currentPage(0)
			.totalPages(1)
			.totalElements(1L)
			.size(20)
			.hasNext(false)
			.hasPrevious(false)
			.build();

		given(adminBadgeService.getAllBadgeApplies(any(Pageable.class))).willReturn(response);

		// when & then
		mockMvc.perform(get("/admin/badge/list")
				.param("page", "0")
				.param("size", "20"))
			.andDo(print())
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.status").value(200))
			.andExpect(jsonPath("$.message").value("OK"))
			.andExpect(jsonPath("$.data.badgeApplies").isArray())
			.andExpect(jsonPath("$.data.badgeApplies[0].badgeApplyId").value(1L))
			.andExpect(jsonPath("$.data.badgeApplies[0].status").value("PENDING"))
			.andExpect(jsonPath("$.data.badgeApplies[0].applicantName").value("홍길동"))
			.andExpect(jsonPath("$.data.currentPage").value(0))
			.andExpect(jsonPath("$.data.totalElements").value(1));
	}

	@Test
	@WithMockUser(authorities = "ROLE_ADMIN")
	@DisplayName("관리자는 상태별로 배지 신청 목록을 필터링할 수 있다")
	void getBadgeAppliesByStatus() throws Exception {
		// given
		BadgeApplyListItemResponse item = BadgeApplyListItemResponse.builder()
			.badgeApplyId(1L)
			.status(Status.PENDING)
			.applicantName("홍길동")
			.applicantPhone("010-1234-5678")
			.businessName("테스트 카페")
			.businessNo("123-45-67890")
			.badgeCategory(Category.ENVIRONMENT_PROTECTION)
			.appliedAt(LocalDateTime.now())
			.build();

		BadgeApplyListResponse response = BadgeApplyListResponse.builder()
			.badgeApplies(List.of(item))
			.currentPage(0)
			.totalPages(1)
			.totalElements(1L)
			.size(20)
			.hasNext(false)
			.hasPrevious(false)
			.build();

		given(adminBadgeService.getBadgeAppliesByStatus(eq(Status.PENDING),
			any(Pageable.class)))
			.willReturn(response);

		// when & then
		mockMvc.perform(get("/admin/badge/list")
				.param("status", "PENDING")
				.param("page", "0")
				.param("size", "20"))
			.andDo(print())
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.status").value(200))
			.andExpect(jsonPath("$.message").value("OK"))
			.andExpect(jsonPath("$.data.badgeApplies[0].status").value("PENDING"));
	}

	@Test
	@WithMockUser(authorities = "ROLE_ADMIN")
	@DisplayName("관리자는 특정 배지 신청의 상세 정보를 조회할 수 있다")
	void getBadgeApplyDetail() throws Exception {
		// given
		BadgeApply badgeApply = mock(BadgeApply.class);
		given(badgeApply.getId()).willReturn(1L);
		given(badgeApply.getStatus()).willReturn(Status.PENDING);
		given(adminBadgeService.getBadgeApplyDetail(1L)).willReturn(badgeApply);

		// when & then
		mockMvc.perform(get("/admin/badge/1"))
			.andDo(print())
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.status").value(200))
			.andExpect(jsonPath("$.message").value("OK"))
			.andExpect(jsonPath("$.data.id").value(1L))
			.andExpect(jsonPath("$.data.status").value("PENDING"));
	}

	@Test
	@WithMockUser(authorities = "ROLE_ADMIN")
	@DisplayName("존재하지 않는 배지 신청 조회 시 404 에러를 반환한다")
	void getBadgeApplyDetail_NotFound() throws Exception {
		// given
		given(adminBadgeService.getBadgeApplyDetail(999L))
			.willThrow(new
				CustomException(AdminErrorCode.BADGE_APPLY_NOT_FOUND));

		// when & then
		mockMvc.perform(get("/admin/badge/999"))
			.andDo(print())
			.andExpect(status().isNotFound())
			.andExpect(jsonPath("$.message").value("신청 내역을 찾을 수 없습니다."))
			.andExpect(jsonPath("$.code").value("P-001"));
	}
}