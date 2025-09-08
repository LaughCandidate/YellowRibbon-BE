package laughcandidate.yellowribbonbe.user.repository.custom;

import org.springframework.stereotype.Repository;

import com.querydsl.core.types.Projections;
import com.querydsl.jpa.impl.JPAQueryFactory;

import laughcandidate.yellowribbonbe.business.entity.QBusiness;
import laughcandidate.yellowribbonbe.user.dto.response.UserBusinessInfo;
import laughcandidate.yellowribbonbe.user.entity.QUser;
import lombok.RequiredArgsConstructor;

@Repository
@RequiredArgsConstructor
public class UserBusinessInfoCustomImpl implements UserBusinessInfoCustom {

	private final JPAQueryFactory queryFactory;

	@Override
	public UserBusinessInfo findUserBusinessInfoWithId(String id) {
		QUser user = QUser.user;
		QBusiness business = QBusiness.business;

		return queryFactory
			.select(Projections.constructor(UserBusinessInfo.class,
				user.id,
				user.uid,
				user.loginId,
				user.password,
				user.role.stringValue(),
				business.id
			))
			.from(user)
			.leftJoin(business).on(business.user.eq(user))
			.where(user.loginId.eq(id)
				.and(user.isDeleted.eq(false)))
			.orderBy(business.id.asc().nullsLast())
			.fetchFirst();
	}
}