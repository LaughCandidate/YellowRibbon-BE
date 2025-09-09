package laughcandidate.yellowribbonbe.product.repository.custom;

import laughcandidate.yellowribbonbe.product.entity.UserBenefitProduct;

import java.util.List;

public interface UserBenefitProductRepositoryCustom {
    List<UserBenefitProduct> findActiveUserBenefitProductsByUserId(Long userId);
}
