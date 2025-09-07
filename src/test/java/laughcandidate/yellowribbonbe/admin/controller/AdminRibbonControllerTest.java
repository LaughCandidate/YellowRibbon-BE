package laughcandidate.yellowribbonbe.admin.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import laughcandidate.yellowribbonbe.admin.dto.response.RibbonIssueListItemResponse;
import laughcandidate.yellowribbonbe.admin.dto.response.RibbonIssueListResponse;
import laughcandidate.yellowribbonbe.admin.service.AdminRibbonService;
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
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ActiveProfiles("test")
@WebMvcTest(AdminRibbonController.class)
class AdminRibbonControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AdminRibbonService adminRibbonService;

    @Test
    @WithMockUser(authorities = "ROLE_ADMIN")
    @DisplayName("관리자는 리본 발급 내역 목록을 조회할 수 있다")
    void getRibbonIssues() throws Exception {
        // given
        RibbonIssueListItemResponse item = RibbonIssueListItemResponse.builder()
                .ribbonSuccessId(1L)
                .businessName("테스트 카페")
                .businessNo("123-45-67890")
                .issuedAt(LocalDateTime.now())
                .build();

        RibbonIssueListResponse response = RibbonIssueListResponse.builder()
                .ribbonIssues(List.of(item))
                .currentPage(0)
                .totalPages(1)
                .totalElements(1L)
                .size(20)
                .hasNext(false)
                .hasPrevious(false)
                .build();

        given(adminRibbonService.getAllRibbonIssues(any(Pageable.class))).willReturn(response);

        // when & then
        mockMvc.perform(get("/admin/ribbon/list")
                        .param("page", "0")
                        .param("size", "20"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(200))
                .andExpect(jsonPath("$.message").value("OK"))
                .andExpect(jsonPath("$.data.ribbonIssues").isArray())
                .andExpect(jsonPath("$.data.ribbonIssues[0].ribbonSuccessId").value(1L))
                .andExpect(jsonPath("$.data.ribbonIssues[0].businessName").value("테스트 카페"))
                .andExpect(jsonPath("$.data.ribbonIssues[0].businessNo").value("123-45-67890"))
                .andExpect(jsonPath("$.data.currentPage").value(0))
                .andExpect(jsonPath("$.data.totalElements").value(1));
    }

    @Test
    @WithMockUser(authorities = "ROLE_ADMIN")
    @DisplayName("페이지네이션 파라미터가 정상적으로 처리된다")
    void getRibbonIssues_WithPagination() throws Exception {
        // given
        RibbonIssueListResponse response = RibbonIssueListResponse.builder()
                .ribbonIssues(List.of())
                .currentPage(1)
                .totalPages(3)
                .totalElements(25L)
                .size(10)
                .hasNext(true)
                .hasPrevious(true)
                .build();

        given(adminRibbonService.getAllRibbonIssues(any(Pageable.class))).willReturn(response);

        // when & then
        mockMvc.perform(get("/admin/ribbon/list")
                        .param("page", "1")
                        .param("size", "10")
                        .param("sort", "createdAt,desc"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(200))
                .andExpect(jsonPath("$.message").value("OK"))
                .andExpect(jsonPath("$.data.currentPage").value(1))
                .andExpect(jsonPath("$.data.totalPages").value(3))
                .andExpect(jsonPath("$.data.totalElements").value(25))
                .andExpect(jsonPath("$.data.size").value(10))
                .andExpect(jsonPath("$.data.hasNext").value(true))
                .andExpect(jsonPath("$.data.hasPrevious").value(true));
    }

    @Test
    @WithMockUser(authorities = "ROLE_ADMIN")
    @DisplayName("빈 리본 발급 내역 조회 시 빈 목록을 반환한다")
    void getRibbonIssues_EmptyResult() throws Exception {
        // given
        RibbonIssueListResponse response = RibbonIssueListResponse.builder()
                .ribbonIssues(List.of())
                .currentPage(0)
                .totalPages(0)
                .totalElements(0L)
                .size(20)
                .hasNext(false)
                .hasPrevious(false)
                .build();

        given(adminRibbonService.getAllRibbonIssues(any(Pageable.class))).willReturn(response);

        // when & then
        mockMvc.perform(get("/admin/ribbon/list"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(200))
                .andExpect(jsonPath("$.message").value("OK"))
                .andExpect(jsonPath("$.data.ribbonIssues").isArray())
                .andExpect(jsonPath("$.data.ribbonIssues").isEmpty())
                .andExpect(jsonPath("$.data.totalElements").value(0));
    }
}