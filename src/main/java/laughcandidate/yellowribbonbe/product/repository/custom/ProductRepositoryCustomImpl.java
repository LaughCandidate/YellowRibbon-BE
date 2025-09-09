package laughcandidate.yellowribbonbe.product.repository.custom;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import laughcandidate.yellowribbonbe.product.entity.Product;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;

import static laughcandidate.yellowribbonbe.product.entity.QProduct.product;

@Repository
@RequiredArgsConstructor
public class ProductRepositoryCustomImpl implements ProductRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public List<Product> findFilteredProducts(ProductCategory category, Long badgeId) {
        return queryFactory
                .selectFrom(product)
                .leftJoin(product.badge).fetchJoin()
                .where(
                    typeEquals(category),
                    badgeEquals(badgeId)
                )
                .fetch();
    }

    private BooleanExpression typeEquals(ProductCategory category) {
        if (category == null) {
            return null;
        }

        return switch (category) {
            case LOAN -> product.instanceOf(laughcandidate.yellowribbonbe.product.entity.LoanProduct.class);
            case DEPOSIT -> product.instanceOf(laughcandidate.yellowribbonbe.product.entity.DepositProduct.class);
            case SAVINGS -> product.instanceOf(laughcandidate.yellowribbonbe.product.entity.InstallmentSavingProduct.class);
            case INSURANCE -> product.instanceOf(laughcandidate.yellowribbonbe.product.entity.InsuranceProduct.class);
        };
    }

    private BooleanExpression badgeEquals(Long badgeId) {
        return badgeId != null ? product.badge.id.eq(badgeId) : null;
    }
}
