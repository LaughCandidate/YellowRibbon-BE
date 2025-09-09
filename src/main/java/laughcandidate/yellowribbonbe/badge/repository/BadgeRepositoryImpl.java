package laughcandidate.yellowribbonbe.badge.repository;

import com.querydsl.jpa.impl.JPAQueryFactory;
import laughcandidate.yellowribbonbe.badge.entity.Badge;
import lombok.RequiredArgsConstructor;

import java.util.List;

import static laughcandidate.yellowribbonbe.badge.entity.QBadge.badge;
import static laughcandidate.yellowribbonbe.mission.entity.QMission.mission;

@RequiredArgsConstructor
public class BadgeRepositoryImpl implements BadgeRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public List<Badge> findAllWithMissions() {
        return queryFactory
                .selectFrom(badge)
                .leftJoin(mission).on(mission.badge.eq(badge)).fetchJoin()
                .fetch();
    }
}