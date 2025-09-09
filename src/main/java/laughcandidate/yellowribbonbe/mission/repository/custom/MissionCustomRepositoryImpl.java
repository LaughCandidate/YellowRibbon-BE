package laughcandidate.yellowribbonbe.mission.repository.custom;

import com.querydsl.core.types.Projections;
import com.querydsl.jpa.impl.JPAQueryFactory;
import laughcandidate.yellowribbonbe.mission.dto.response.MissionInfoDto;
import laughcandidate.yellowribbonbe.mission.entity.QMission;
import laughcandidate.yellowribbonbe.mission.entity.QMissionSubmit;
import laughcandidate.yellowribbonbe.badge.entity.QBadge;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class MissionCustomRepositoryImpl implements MissionCustomRepository {
    
    private final JPAQueryFactory queryFactory;
    
    @Override
    public List<MissionInfoDto> findMissionWithSubmitData(Long badgeId, Long businessId) {
        QMissionSubmit missionSubmit = QMissionSubmit.missionSubmit;
        QMission mission = QMission.mission;
        QBadge badge = QBadge.badge;
        
        return queryFactory
                .select(Projections.constructor(MissionInfoDto.class,
                        missionSubmit.reason,
                        missionSubmit.status,
                        mission.description,
                        mission.id,
                        badge.category,
                        missionSubmit.id.isNotNull()
                ))
                .from(mission)
                .join(mission.badge, badge)
                .leftJoin(missionSubmit).on(missionSubmit.mission.id.eq(mission.id)
                        .and(missionSubmit.business.id.eq(businessId))
                        .and(missionSubmit.id.in(
                                queryFactory
                                        .select(missionSubmit.id.max())
                                        .from(missionSubmit)
                                        .where(missionSubmit.mission.id.eq(mission.id)
                                                .and(missionSubmit.business.id.eq(businessId)))
                                        .groupBy(missionSubmit.mission.id)
                        )))
                .where(badge.id.eq(badgeId))
                .fetch();
    }
}