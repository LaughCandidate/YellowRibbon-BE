package laughcandidate.yellowribbonbe.mydata.entity;

import jakarta.persistence.*;
import laughcandidate.yellowribbonbe.global.entity.BaseEntity;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;
import laughcandidate.yellowribbonbe.user.entity.User;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "MYDATA")
@Inheritance(strategy = InheritanceType.JOINED)
@DiscriminatorColumn(name = "category")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class MyData extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "my_data_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "product_name")
    private String productName;

    protected MyData(User user, String productName) {
        this.user = user;
        this.productName = productName;
    }

    public abstract ProductCategory getCategory();
}
