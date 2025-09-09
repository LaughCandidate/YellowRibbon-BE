package laughcandidate.yellowribbonbe.yellowRibbon.repository;

import com.querydsl.jpa.impl.JPAQueryFactory;
import laughcandidate.yellowribbonbe.yellowRibbon.entity.YellowRibbon;
import lombok.RequiredArgsConstructor;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Optional;

import static laughcandidate.yellowribbonbe.yellowRibbon.entity.QYellowRibbon.yellowRibbon;

@RequiredArgsConstructor
public class YellowRibbonRepositoryImpl implements YellowRibbonRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public Optional<YellowRibbon> findCurrentSeason() {
        int year = LocalDate.now(ZoneId.of("Asia/Seoul")).getYear();

        YellowRibbon result = queryFactory
                .selectFrom(yellowRibbon)
                .where(yellowRibbon.season.eq(year))
                .fetchOne();

        return Optional.ofNullable(result);
    }
}