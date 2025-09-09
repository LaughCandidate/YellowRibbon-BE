package laughcandidate.yellowribbonbe.product.repository.custom;

import laughcandidate.yellowribbonbe.product.entity.Product;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;
import java.util.List;

public interface ProductRepositoryCustom {
    List<Product> findFilteredProducts(ProductCategory category, Long badgeId);
}
