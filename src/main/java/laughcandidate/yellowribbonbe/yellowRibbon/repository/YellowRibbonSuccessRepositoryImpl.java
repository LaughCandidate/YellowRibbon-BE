package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;

import java.util.List;

import static laughcandidate.yellowribbonbe.yellowRibbon.entity.QYellowRibbon.yellowRibbon;
import static laughcandidate.yellowribbonbe.yellowRibbon.entity.QYellowRibbonSuccess.yellowRibbonSuccess;
import static laughcandidate.yellowribbonbe.business.entity.QBusiness.business;
import static laughcandidate.yellowribbonbe.user.entity.QUser.user;

@RequiredArgsConstructor
public class YellowRibbonSuccessRepositoryImpl implements YellowRibbonSuccessRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public Page<YellowRibbonSuccess> findAllWithBusinessInfo(Pageable pageable) {
        List<YellowRibbonSuccess> content = queryFactory
                .selectFrom(yellowRibbonSuccess)
                .join(yellowRibbonSuccess.user, user).fetchJoin()
                .join(yellowRibbonSuccess.business, business).fetchJoin()
                .orderBy(yellowRibbonSuccess.createdAt.desc())
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        JPAQuery<Long> countQuery = queryFactory
                .select(yellowRibbonSuccess.count())
                .from(yellowRibbonSuccess);

        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchOne);
    }

    @Override
    public List<YellowRibbon> findRibbonsByBusinessId(Long businessId) {
        return queryFactory
                .select(yellowRibbon)
                .from(yellowRibbonSuccess)
                .join(yellowRibbonSuccess.yellowRibbon, yellowRibbon)
                .where(yellowRibbonSuccess.business.id.eq(businessId))
                .distinct()
                .orderBy(yellowRibbon.id.asc())
                .fetch();
    }
}