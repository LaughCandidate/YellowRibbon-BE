package laughcandidate.yellowribbonbe.mission.repository.custom;

import com.querydsl.core.types.Projections;
import com.querydsl.jpa.impl.JPAQueryFactory;
import laughcandidate.yellowribbonbe.badge.entity.QBadge;
import laughcandidate.yellowribbonbe.global.entity.Status;
import laughcandidate.yellowribbonbe.image.entity.QImage;
import laughcandidate.yellowribbonbe.mission.dto.response.MissionInfoDto;
import laughcandidate.yellowribbonbe.mission.entity.Mission;
import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;
import laughcandidate.yellowribbonbe.mission.entity.QMission;
import laughcandidate.yellowribbonbe.mission.entity.QMissionSubmit;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class MissionCustomRepositoryImpl implements MissionCustomRepository {

    private final JPAQueryFactory queryFactory;

    private static final QMission mission = QMission.mission;
    private static final QMissionSubmit missionSubmit = QMissionSubmit.missionSubmit;
    private static final QBadge badge = QBadge.badge;
    private static final QImage image = QImage.image;

    @Override
    public List<MissionInfoDto> findMissionWithSubmitData(Long badgeId, Long businessId) {
        QMissionSubmit ms2 = new QMissionSubmit("ms2");

        return queryFactory
                .select(Projections.constructor(MissionInfoDto.class,
                        missionSubmit.reason,
                        missionSubmit.status,
                        mission.description,
                        mission.id,
                        badge.category,
                        missionSubmit.id.isNotNull(),
                        missionSubmit.id,
                        image.id,
                        missionSubmit.createdAt
                ))
                .from(mission)
                .join(mission.badge, badge)
                .leftJoin(missionSubmit).on(
                        missionSubmit.mission.id.eq(mission.id)
                                .and(missionSubmit.business.id.eq(businessId))
                                .and(missionSubmit.id.in(
                                        queryFactory
                                                .select(ms2.id.max())
                                                .from(ms2)
                                                .where(ms2.mission.id.eq(mission.id)
                                                        .and(ms2.business.id.eq(businessId)))
                                                .groupBy(ms2.mission.id)
                                ))
                )
                .leftJoin(image).on(image.missionSubmit.id.eq(missionSubmit.id))
                .where(badge.id.eq(badgeId))
                .fetch();
    }

    @Override
    public List<MissionSubmit> findByBusinessIdWithDetails(Long businessId) {
        return queryFactory
                .selectFrom(missionSubmit)
                .join(missionSubmit.mission, mission).fetchJoin()
                .where(missionSubmit.business.id.eq(businessId))
                .orderBy(missionSubmit.createdAt.desc())
                .fetch();
    }

    @Override
    public List<Mission> findCompletedMission(Long businessId, Integer targetSeason) {
        QMission m2 = new QMission("m2");
        
        return queryFactory
                .selectFrom(mission)
                .join(mission.badge, badge).fetchJoin()
                .where(mission.season.eq(targetSeason)
                        .and(mission.id.in(
                                queryFactory
                                        .select(m2.id.max())
                                        .from(m2)
                                        .where(m2.season.eq(targetSeason))
                                        .groupBy(m2.badge.id)
                        )))
                .orderBy(badge.id.asc())
                .fetch();
    }
}
