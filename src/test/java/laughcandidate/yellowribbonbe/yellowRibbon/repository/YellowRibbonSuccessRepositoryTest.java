package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import laughcandidate.yellowribbonbe.business.entity.Business;
import laughcandidate.yellowribbonbe.business.repository.BusinessRepository;
import laughcandidate.yellowribbonbe.user.entity.Role;
import laughcandidate.yellowribbonbe.user.entity.User;
import laughcandidate.yellowribbonbe.user.repository.UserRepository;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Constructor;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.*;

@ActiveProfiles("test")
@DataJpaTest
@EnableJpaAuditing
class YellowRibbonSuccessRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private YellowRibbonSuccessRepository yellowRibbonSuccessRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BusinessRepository businessRepository;

    private User testUser;
    private Business testBusiness;
    private YellowRibbon testYellowRibbon;

    @BeforeEach
    void setUp() throws Exception {
        testUser = User.builder()
                .name("홍길동")
                .loginId("testuser")
                .password("password123")
                .phone("010-1234-5678")
                .uid("test-uid")
                .role(Role.USER)
                .build();
        entityManager.persistAndFlush(testUser);

        testBusiness = Business.builder()
                .businessName("테스트 카페")
                .businessNo("123-45-67890")
                .ownerName("홍길동")
                .startDate(LocalDate.now())
                .user(testUser)
                .build();
        entityManager.persistAndFlush(testBusiness);

        Constructor<YellowRibbon> constructor = YellowRibbon.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        testYellowRibbon = constructor.newInstance();
        ReflectionTestUtils.setField(testYellowRibbon, "benefit", "환경보호 혜택");
        ReflectionTestUtils.setField(testYellowRibbon, "season", 1);
        entityManager.persist(testYellowRibbon);
        entityManager.flush();
    }

    @Test
    @DisplayName("비즈니스 정보와 함께 리본 발급 내역을 최신순으로 페이지네이션 조회한다")
    void findAllWithBusinessInfo() {
        // given
        YellowRibbonSuccess success1 = createYellowRibbonSuccess();
        YellowRibbonSuccess success2 = createYellowRibbonSuccess();
        YellowRibbonSuccess success3 = createYellowRibbonSuccess();

        Pageable pageable = PageRequest.of(0, 10);

        // when
        Page<YellowRibbonSuccess> result = yellowRibbonSuccessRepository.findAllWithBusinessInfo(pageable);

        // then
        assertThat(result.getContent()).hasSize(3);
        assertThat(result.getTotalElements()).isEqualTo(3);
        assertThat(result.getNumber()).isEqualTo(0);
        assertThat(result.getSize()).isEqualTo(10);

        // 연관 엔티티가 함께 조회되는지 확인 (JOIN FETCH 테스트)
        YellowRibbonSuccess firstSuccess = result.getContent().get(0);
        assertThat(firstSuccess.getBusiness()).isNotNull();
        assertThat(firstSuccess.getBusiness().getBusinessName()).isEqualTo("테스트 카페");
        assertThat(firstSuccess.getBusiness().getBusinessNo()).isEqualTo("123-45-67890");
    }

    @Test
    @DisplayName("페이지네이션이 정확히 동작한다")
    void paginationTest() {
        // given
        for (int i = 0; i < 25; i++) {
            createYellowRibbonSuccess();
        }

        Pageable firstPage = PageRequest.of(0, 10);
        Pageable secondPage = PageRequest.of(1, 10);
        Pageable thirdPage = PageRequest.of(2, 10);

        // when
        Page<YellowRibbonSuccess> page1 = yellowRibbonSuccessRepository.findAllWithBusinessInfo(firstPage);
        Page<YellowRibbonSuccess> page2 = yellowRibbonSuccessRepository.findAllWithBusinessInfo(secondPage);
        Page<YellowRibbonSuccess> page3 = yellowRibbonSuccessRepository.findAllWithBusinessInfo(thirdPage);

        // then
        assertThat(page1.getContent()).hasSize(10);
        assertThat(page1.getTotalPages()).isEqualTo(3);
        assertThat(page1.hasNext()).isTrue();
        assertThat(page1.hasPrevious()).isFalse();

        assertThat(page2.getContent()).hasSize(10);
        assertThat(page2.hasNext()).isTrue();
        assertThat(page2.hasPrevious()).isTrue();

        assertThat(page3.getContent()).hasSize(5);
        assertThat(page3.hasNext()).isFalse();
        assertThat(page3.hasPrevious()).isTrue();
    }

    @Test
    @DisplayName("리본 발급 내역이 없을 때 빈 페이지를 반환한다")
    void findAllWithBusinessInfo_EmptyResult() {
        // given
        Pageable pageable = PageRequest.of(0, 10);

        // when
        Page<YellowRibbonSuccess> result = yellowRibbonSuccessRepository.findAllWithBusinessInfo(pageable);

        // then
        assertThat(result.getContent()).isEmpty();
        assertThat(result.getTotalElements()).isEqualTo(0);
        assertThat(result.getTotalPages()).isEqualTo(0);
        assertThat(result.hasNext()).isFalse();
        assertThat(result.hasPrevious()).isFalse();
    }

    private YellowRibbonSuccess createYellowRibbonSuccess() {
        try {
            Constructor<YellowRibbonSuccess> constructor = YellowRibbonSuccess.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            YellowRibbonSuccess yellowRibbonSuccess = constructor.newInstance();
            ReflectionTestUtils.setField(yellowRibbonSuccess, "user", testUser);
            ReflectionTestUtils.setField(yellowRibbonSuccess, "business", testBusiness);
            ReflectionTestUtils.setField(yellowRibbonSuccess, "yellowRibbon", testYellowRibbon);
            return entityManager.persistAndFlush(yellowRibbonSuccess);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}