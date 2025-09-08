package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import com.querydsl.jpa.impl.JPAQueryFactory;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import lombok.RequiredArgsConstructor;

import java.util.Optional;

import static laughcandidate.yellowribbonbe.yellowRibbon.entity.QYellowRibbon.yellowRibbon;

@RequiredArgsConstructor
public class YellowRibbonRepositoryImpl implements YellowRibbonRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public Optional<YellowRibbon> findCurrentSeason() {
        YellowRibbon result = queryFactory
                .selectFrom(yellowRibbon)
                .orderBy(yellowRibbon.season.desc())
                .limit(1)
                .fetchOne();

        return Optional.ofNullable(result);
    }
}