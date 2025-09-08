package laughcandidate.yellowribbonbe.product.repository;

import laughcandidate.yellowribbonbe.product.entity.Product;
import laughcandidate.yellowribbonbe.product.repository.custom.ProductRepositoryCustom;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product, Long>, ProductRepositoryCustom {

}
