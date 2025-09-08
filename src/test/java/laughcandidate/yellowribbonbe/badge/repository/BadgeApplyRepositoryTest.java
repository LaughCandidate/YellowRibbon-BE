package laughcandidate.yellowribbonbe.badge.repository;

import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.badge.entity.Badge;
import laughcandidate.yellowribbonbe.badge.entity.Category;
import laughcandidate.yellowribbonbe.badge.entity.Status;
import laughcandidate.yellowribbonbe.business.entity.Business;
import laughcandidate.yellowribbonbe.business.repository.BusinessRepository;
import laughcandidate.yellowribbonbe.user.entity.Role;
import laughcandidate.yellowribbonbe.user.entity.User;
import laughcandidate.yellowribbonbe.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.context.annotation.Import;
import laughcandidate.yellowribbonbe.global.config.QueryDslConfig;
import java.lang.reflect.Constructor;
import java.time.LocalDate;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

@ActiveProfiles("test")
@DataJpaTest
@EnableJpaAuditing
@Import(QueryDslConfig.class)
class BadgeApplyRepositoryTest {

	@Autowired
	private TestEntityManager entityManager;

	@Autowired
	private BadgeApplyRepository badgeApplyRepository;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private BusinessRepository businessRepository;

	private User testUser;
	private Business testBusiness;
	private Badge testBadge;

	@BeforeEach
	void setUp() throws Exception {
		testUser = User.builder()
			.name("홍길동")
			.loginId("testuser")
			.password("password123")
			.phone("010-1234-5678")
			.uid("test-uid")
			.role(Role.ROLE_USER)
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

		Constructor<Badge> constructor = Badge.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		testBadge = constructor.newInstance();
		ReflectionTestUtils.setField(testBadge, "category", Category.ENVIRONMENT_PROTECTION);
		entityManager.persist(testBadge);
		entityManager.flush();
	}

	@Test
	@DisplayName("모든 배지 신청을 최신순으로 페이지네이션 조회한다")
	void findAllWithBasicInfo() {
		// given
		BadgeApply badgeApply1 = createBadgeApply(Status.PENDING);
		BadgeApply badgeApply2 = createBadgeApply(Status.COMPLETE);
		BadgeApply badgeApply3 = createBadgeApply(Status.REJECTED);

		Pageable pageable = PageRequest.of(0, 10);

		// when
		Page<BadgeApply> result = badgeApplyRepository.findAllWithBasicInfo(pageable);

		// then
		assertThat(result.getContent()).hasSize(3);
		assertThat(result.getTotalElements()).isEqualTo(3);
		assertThat(result.getNumber()).isEqualTo(0);
		assertThat(result.getSize()).isEqualTo(10);

		BadgeApply firstApply = result.getContent().get(0);
		assertThat(firstApply.getUser()).isNotNull();
		assertThat(firstApply.getBadge()).isNotNull();
		assertThat(firstApply.getBusiness()).isNotNull();
	}

	@Test
	@DisplayName("특정 상태의 배지 신청을 페이지네이션으로 조회한다")
	void findByStatusWithBasicInfo() {
		// given
		createBadgeApply(Status.PENDING);
		createBadgeApply(Status.PENDING);
		createBadgeApply(Status.COMPLETE);

		Pageable pageable = PageRequest.of(0, 10);

		// when
		Page<BadgeApply> result = badgeApplyRepository.findByStatusWithBasicInfo(Status.PENDING, pageable);

		// then
		assertThat(result.getContent()).hasSize(2);
		assertThat(result.getTotalElements()).isEqualTo(2);

		assertThat(result.getContent())
			.allMatch(apply -> apply.getStatus() == Status.PENDING);
	}

	@Test
	@DisplayName("ID로 배지 신청 상세 정보를 조회한다")
	void findByIdWithAllDetails() {
		// given
		BadgeApply savedApply = createBadgeApply(Status.PENDING);

		// when
		Optional<BadgeApply> result = badgeApplyRepository.findByIdWithAllDetails(savedApply.getId());

		// then
		assertThat(result).isPresent();
		BadgeApply foundApply = result.get();
		assertThat(foundApply.getId()).isEqualTo(savedApply.getId());
		assertThat(foundApply.getStatus()).isEqualTo(Status.PENDING);
		assertThat(foundApply.getUser()).isNotNull();
		assertThat(foundApply.getUser().getName()).isEqualTo("홍길동");
		assertThat(foundApply.getBusiness()).isNotNull();
		assertThat(foundApply.getBusiness().getBusinessName()).isEqualTo("테스트 카페");
		assertThat(foundApply.getBadge()).isNotNull();
	}

	@Test
	@DisplayName("존재하지 않는 ID로 조회하면 빈 Optional을 반환한다")
	void findByIdWithAllDetails_NotFound() {
		// when
		Optional<BadgeApply> result = badgeApplyRepository.findByIdWithAllDetails(999L);

		// then
		assertThat(result).isEmpty();
	}

	@Test
	@DisplayName("페이지네이션이 정확히 동작한다")
	void paginationTest() {
		// given
		for (int i = 0; i < 25; i++) {
			createBadgeApply(Status.PENDING);
		}

		Pageable firstPage = PageRequest.of(0, 10);
		Pageable secondPage = PageRequest.of(1, 10);
		Pageable thirdPage = PageRequest.of(2, 10);

		// when
		Page<BadgeApply> page1 = badgeApplyRepository.findAllWithBasicInfo(firstPage);
		Page<BadgeApply> page2 = badgeApplyRepository.findAllWithBasicInfo(secondPage);
		Page<BadgeApply> page3 = badgeApplyRepository.findAllWithBasicInfo(thirdPage);

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

	private BadgeApply createBadgeApply(Status status) {
		BadgeApply badgeApply = BadgeApply.builder()
			.user(testUser)
			.business(testBusiness)
			.badge(testBadge)
			.status(status)
			.build();

		return entityManager.persistAndFlush(badgeApply);
	}
}