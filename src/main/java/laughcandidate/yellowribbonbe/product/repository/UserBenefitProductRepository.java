package laughcandidate.yellowribbonbe.product.repository;

import laughcandidate.yellowribbonbe.product.entity.UserBenefitProduct;
import laughcandidate.yellowribbonbe.product.repository.custom.UserBenefitProductRepositoryCustom;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserBenefitProductRepository extends JpaRepository<UserBenefitProduct, Long>, UserBenefitProductRepositoryCustom {
}
