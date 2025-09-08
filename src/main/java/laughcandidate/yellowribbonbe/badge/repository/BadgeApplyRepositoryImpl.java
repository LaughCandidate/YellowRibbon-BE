package laughcandidate.yellowribbonbe.badge.repository;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import laughcandidate.yellowribbonbe.badge.entity.BadgeApply;
import laughcandidate.yellowribbonbe.global.entity.Status;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;

import java.util.List;
import java.util.Optional;

import static laughcandidate.yellowribbonbe.badge.entity.QBadgeApply.badgeApply;
import static laughcandidate.yellowribbonbe.badge.entity.QBadge.badge;
import static laughcandidate.yellowribbonbe.business.entity.QBusiness.business;
import static laughcandidate.yellowribbonbe.user.entity.QUser.user;

@RequiredArgsConstructor
public class BadgeApplyRepositoryImpl implements BadgeApplyRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public Page<BadgeApply> findAllWithBasicInfo(Pageable pageable) {
        List<BadgeApply> content = queryFactory
                .selectFrom(badgeApply)
                .join(badgeApply.user, user).fetchJoin()
                .join(badgeApply.badge, badge).fetchJoin()
                .join(badgeApply.business, business).fetchJoin()
                .orderBy(badgeApply.createdAt.desc())
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        JPAQuery<Long> countQuery = queryFactory
                .select(badgeApply.count())
                .from(badgeApply);

        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchOne);
    }

    @Override
    public Page<BadgeApply> findByStatusWithBasicInfo(Status status, Pageable pageable) {
        List<BadgeApply> content = queryFactory
                .selectFrom(badgeApply)
                .join(badgeApply.user, user).fetchJoin()
                .join(badgeApply.badge, badge).fetchJoin()
                .join(badgeApply.business, business).fetchJoin()
                .where(statusEq(status))
                .orderBy(badgeApply.createdAt.desc())
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        JPAQuery<Long> countQuery = queryFactory
                .select(badgeApply.count())
                .from(badgeApply)
                .where(statusEq(status));

        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchOne);
    }

    @Override
    public Optional<BadgeApply> findByIdWithAllDetails(Long badgeApplyId) {
        BadgeApply result = queryFactory
                .selectFrom(badgeApply)
                .join(badgeApply.user, user).fetchJoin()
                .join(badgeApply.badge, badge).fetchJoin()
                .join(badgeApply.business, business).fetchJoin()
                .where(badgeApply.id.eq(badgeApplyId))
                .fetchOne();

        return Optional.ofNullable(result);
    }

    private BooleanExpression statusEq(Status status) {
        return status != null ? badgeApply.status.eq(status) : null;
    }
}