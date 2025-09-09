package laughcandidate.yellowribbonbe.product.repository.custom;

import com.querydsl.jpa.impl.JPAQueryFactory;
import laughcandidate.yellowribbonbe.product.entity.UserBenefitProduct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;

import static laughcandidate.yellowribbonbe.product.entity.QUserBenefitProduct.userBenefitProduct;
import static laughcandidate.yellowribbonbe.product.entity.QProduct.product;

@Repository
@RequiredArgsConstructor
public class UserBenefitProductRepositoryCustomImpl implements UserBenefitProductRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public List<UserBenefitProduct> findActiveUserBenefitProductsByUserId(Long userId) {
        return queryFactory
                .selectFrom(userBenefitProduct)
                .join(userBenefitProduct.product, product).fetchJoin()
                .where(
                    userBenefitProduct.user.id.eq(userId)
                    .and(userBenefitProduct.isActive.isTrue())
                )
                .fetch();
    }
}
