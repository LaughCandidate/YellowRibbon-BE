package laughcandidate.yellowribbonbe.admin.service;

import laughcandidate.yellowribbonbe.admin.dto.response.BadgeApplyListResponse;
import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.badge.entity.Badge;
import laughcandidate.yellowribbonbe.badge.entity.Status;
import laughcandidate.yellowribbonbe.badge.repository.BadgeApplyRepository;
import laughcandidate.yellowribbonbe.business.entity.Business;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AdminErrorCode;
import laughcandidate.yellowribbonbe.user.entity.Role;
import laughcandidate.yellowribbonbe.user.entity.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ActiveProfiles("test")
@ExtendWith(MockitoExtension.class)
class AdminBadgeServiceTest {

	@InjectMocks
	private AdminBadgeService adminBadgeService;

	@Mock
	private BadgeApplyRepository badgeApplyRepository;

	@Test
	@DisplayName("모든 배지 신청 목록을 페이지네이션으로 조회한다")
	void getAllBadgeApplies() {
		// given
		Pageable pageable = PageRequest.of(0, 20);
		List<BadgeApply> badgeApplies = List.of(createMockBadgeApply());
		Page<BadgeApply> page = new PageImpl<>(badgeApplies, pageable, 1);
		given(badgeApplyRepository.findAllWithBasicInfo(pageable)).willReturn(page);

		// when
		BadgeApplyListResponse result = adminBadgeService.getAllBadgeApplies(pageable);

		// then
		assertThat(result.badgeApplies()).hasSize(1);
		assertThat(result.totalElements()).isEqualTo(1);
		assertThat(result.currentPage()).isEqualTo(0);
		verify(badgeApplyRepository).findAllWithBasicInfo(pageable);
	}

	@Test
	@DisplayName("상태별 배지 신청 목록을 페이지네이션으로 조회한다")
	void getBadgeAppliesByStatus() {
		// given
		Status status = Status.PENDING;
		Pageable pageable = PageRequest.of(0, 20);
		List<BadgeApply> badgeApplies = List.of(createMockBadgeApply());
		Page<BadgeApply> page = new PageImpl<>(badgeApplies, pageable, 1);
		given(badgeApplyRepository.findByStatusWithBasicInfo(eq(status), eq(pageable))).willReturn(page);

		// when
		BadgeApplyListResponse result = adminBadgeService.getBadgeAppliesByStatus(status, pageable);

		// then
		assertThat(result.badgeApplies()).hasSize(1);
		assertThat(result.badgeApplies().get(0).status()).isEqualTo(Status.PENDING);
		verify(badgeApplyRepository).findByStatusWithBasicInfo(status, pageable);
	}

	@Test
	@DisplayName("배지 신청 상세 정보를 조회한다")
	void getBadgeApplyDetail() {
		// given
		Long badgeApplyId = 1L;
		BadgeApply badgeApply = createMockBadgeApply();
		given(badgeApplyRepository.findByIdWithAllDetails(badgeApplyId)).willReturn(Optional.of(badgeApply));

		// when
		BadgeApply result = adminBadgeService.getBadgeApplyDetail(badgeApplyId);

		// then
		assertThat(result).isNotNull();
		assertThat(result.getStatus()).isEqualTo(Status.PENDING);
		verify(badgeApplyRepository).findByIdWithAllDetails(badgeApplyId);
	}

	@Test
	@DisplayName("존재하지 않는 배지 신청 조회 시 예외를 발생시킨다")
	void getBadgeApplyDetail_NotFound() {
		// given
		Long badgeApplyId = 999L;
		given(badgeApplyRepository.findByIdWithAllDetails(badgeApplyId)).willReturn(Optional.empty());

		// when & then
		assertThatThrownBy(() -> adminBadgeService.getBadgeApplyDetail(badgeApplyId))
			.isInstanceOf(CustomException.class)
			.hasFieldOrPropertyWithValue("errorCode", AdminErrorCode.BADGE_APPLY_NOT_FOUND);

		verify(badgeApplyRepository).findByIdWithAllDetails(badgeApplyId);
	}

	@Test
	@DisplayName("배지 신청을 승인한다")
	void approveBadgeApplication() {
		// given
		Long badgeApplyId = 1L;
		BadgeApply badgeApply = createMockBadgeApply();
		given(badgeApplyRepository.findById(badgeApplyId)).willReturn(Optional.of(badgeApply));

		// when
		adminBadgeService.approveBadgeApplication(badgeApplyId);

		// then
		assertThat(badgeApply.getStatus()).isEqualTo(Status.COMPLETE);
		verify(badgeApplyRepository).findById(badgeApplyId);
	}

	@Test
	@DisplayName("존재하지 않는 배지 신청 승인 시 예외를 발생시킨다")
	void approveBadgeApplication_NotFound() {
		// given
		Long badgeApplyId = 999L;
		given(badgeApplyRepository.findById(badgeApplyId)).willReturn(Optional.empty());

		// when & then
		assertThatThrownBy(() -> adminBadgeService.approveBadgeApplication(badgeApplyId))
			.isInstanceOf(CustomException.class)
			.hasFieldOrPropertyWithValue("errorCode", AdminErrorCode.BADGE_APPLY_NOT_FOUND);

		verify(badgeApplyRepository).findById(badgeApplyId);
	}

	private BadgeApply createMockBadgeApply() {
		User user = User.builder()
			.name("홍길동")
			.phone("010-1234-1234")
			.loginId("testuser")
			.password("password")
			.uid("test_uid")
			.role(Role.USER)
			.build();

		Business business = Business.builder()
			.businessName("테스트 카페")
			.businessNo("123-45-67890")
			.ownerName("홍길동")
			.startDate(LocalDate.now())
			.user(user)
			.build();

		Badge badge = mock(Badge.class);

		return BadgeApply.builder()
			.user(user)
			.business(business)
			.badge(badge)
			.status(Status.PENDING)
			.build();
	}
}