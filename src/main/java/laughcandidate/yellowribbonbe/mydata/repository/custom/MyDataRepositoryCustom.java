package laughcandidate.yellowribbonbe.mydata.repository.custom;

import laughcandidate.yellowribbonbe.mydata.entity.MyData;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;

import java.util.List;

public interface MyDataRepositoryCustom {
    List<MyData> findByUserIdAndCategory(Long userId, ProductCategory category);
    List<MyData> findByUserId(Long userId);
}
