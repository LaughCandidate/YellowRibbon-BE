package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbonSuccess;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;

import java.util.List;

import static laughcandidate.yellowribbonbe.yellowRibbon.entity.QYellowRibbonSuccess.yellowRibbonSuccess;
import static laughcandidate.yellowribbonbe.business.entity.QBusiness.business;

@RequiredArgsConstructor
public class YellowRibbonSuccessRepositoryImpl implements YellowRibbonSuccessRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public Page<YellowRibbonSuccess> findAllWithBusinessInfo(Pageable pageable) {
        List<YellowRibbonSuccess> content = queryFactory
                .selectFrom(yellowRibbonSuccess)
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
}