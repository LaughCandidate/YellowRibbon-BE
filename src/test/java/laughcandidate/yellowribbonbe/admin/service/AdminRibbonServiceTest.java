package laughcandidate.yellowribbonbe.admin.service;

import laughcandidate.yellowribbonbe.admin.dto.response.RibbonIssueListResponse;
import laughcandidate.yellowribbonbe.business.entity.Business;
import laughcandidate.yellowribbonbe.user.entity.Role;
import laughcandidate.yellowribbonbe.user.entity.User;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import laughcandidate.yellowribbonbe.yellowRibbon.repository.YellowRibbonSuccessRepository;
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

import static org.assertj.core.api.Assertions.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ActiveProfiles("test")
@ExtendWith(MockitoExtension.class)
class AdminRibbonServiceTest {

    @InjectMocks
    private AdminRibbonService adminRibbonService;

    @Mock
    private YellowRibbonSuccessRepository yellowRibbonSuccessRepository;

    @Test
    @DisplayName("리본 발급 내역을 페이지네이션으로 조회한다")
    void getAllRibbonIssues() {
        // given
        Pageable pageable = PageRequest.of(0, 20);
        List<YellowRibbonSuccess> ribbonSuccesses = List.of(createMockYellowRibbonSuccess());
        Page<YellowRibbonSuccess> page = new PageImpl<>(ribbonSuccesses, pageable, 1);
        given(yellowRibbonSuccessRepository.findAllWithBusinessInfo(pageable)).willReturn(page);

        // when
        RibbonIssueListResponse result = adminRibbonService.getAllRibbonIssues(pageable);

        // then
        assertThat(result.ribbonIssues()).hasSize(1);
        assertThat(result.totalElements()).isEqualTo(1);
        assertThat(result.currentPage()).isEqualTo(0);
        assertThat(result.ribbonIssues().get(0).businessName()).isEqualTo("테스트 카페");
        assertThat(result.ribbonIssues().get(0).businessNo()).isEqualTo("123-45-67890");
        verify(yellowRibbonSuccessRepository).findAllWithBusinessInfo(pageable);
    }

    @Test
    @DisplayName("리본 발급 내역이 없을 때 빈 목록을 반환한다")
    void getAllRibbonIssues_EmptyResult() {
        // given
        Pageable pageable = PageRequest.of(0, 20);
        Page<YellowRibbonSuccess> page = new PageImpl<>(List.of(), pageable, 0);
        given(yellowRibbonSuccessRepository.findAllWithBusinessInfo(pageable)).willReturn(page);

        // when
        RibbonIssueListResponse result = adminRibbonService.getAllRibbonIssues(pageable);

        // then
        assertThat(result.ribbonIssues()).isEmpty();
        assertThat(result.totalElements()).isEqualTo(0);
        assertThat(result.currentPage()).isEqualTo(0);
        verify(yellowRibbonSuccessRepository).findAllWithBusinessInfo(pageable);
    }

    private YellowRibbonSuccess createMockYellowRibbonSuccess() {
        User user = User.builder()
                .name("홍길동")
                .phone("010-1234-1234")
                .loginId("testuser")
                .password("password")
                .uid("test_uid")
                .role(Role.ROLE_USER)
                .build();

        Business business = Business.builder()
                .businessName("테스트 카페")
                .businessNo("123-45-67890")
                .ownerName("홍길동")
                .startDate(LocalDate.now())
                .user(user)
                .build();

        YellowRibbon yellowRibbon = mock(YellowRibbon.class);

        return mock(YellowRibbonSuccess.class, invocation -> {
            String methodName = invocation.getMethod().getName();
            switch (methodName) {
                case "getId": return 1L;
                case "getBusiness": return business;
                case "getUser": return user;
                case "getYellowRibbon": return yellowRibbon;
                case "getCreatedAt": return java.time.LocalDateTime.now();
                default: return invocation.callRealMethod();
            }
        });
    }
}