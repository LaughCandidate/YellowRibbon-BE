package laughcandidate.yellowribbonbe.mission.repository;

import com.querydsl.jpa.impl.JPAQueryFactory;
import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;
import lombok.RequiredArgsConstructor;

import java.util.List;

import static laughcandidate.yellowribbonbe.mission.entity.QMissionSubmit.missionSubmit;
import static laughcandidate.yellowribbonbe.mission.entity.QMission.mission;
import static laughcandidate.yellowribbonbe.image.entity.QImage.image;

@RequiredArgsConstructor
public class MissionSubmitRepositoryImpl implements MissionSubmitRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public List<MissionSubmit> findByBusinessIdWithDetails(Long businessId) {
        return queryFactory
                .selectFrom(missionSubmit)
                .join(missionSubmit.mission, mission).fetchJoin()
                .join(missionSubmit.image, image).fetchJoin()
                .where(missionSubmit.business.id.eq(businessId))
                .orderBy(missionSubmit.createdAt.desc())
                .fetch();
    }
}