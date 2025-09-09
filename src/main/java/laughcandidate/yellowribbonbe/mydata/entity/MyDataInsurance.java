package laughcandidate.yellowribbonbe.mydata.entity;

import jakarta.persistence.*;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;
import laughcandidate.yellowribbonbe.user.entity.User;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDate;

@Entity
@Table(name = "MYDATA_INSURANCE")
@DiscriminatorValue("INSURANCE")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MyDataInsurance extends MyData {

    @Column(name = "ins_term")
    private Integer insTerm;

    @Column(name = "premium")
    private BigDecimal premium;

    @Column(name = "coverage_type")
    private String coverageType;

    @Column(name = "coverage")
    private BigDecimal coverage;

    @Column(name = "preferential")
    private Integer preferential;

    @Column(name = "start_date")
    private LocalDate startDate;

    @Column(name = "maturity_date")
    private LocalDate maturityDate;

    @Builder
    public MyDataInsurance(User user, String productName, Integer insTerm, BigDecimal premium,
                           String coverageType, BigDecimal coverage, Integer preferential,
                           LocalDate startDate, LocalDate maturityDate) {
        super(user, productName);
        this.insTerm = insTerm;
        this.premium = premium;
        this.coverageType = coverageType;
        this.coverage = coverage;
        this.preferential = preferential;
        this.startDate = startDate;
        this.maturityDate = maturityDate;
    }

    @Override
    public ProductCategory getCategory() {
        return ProductCategory.INSURANCE;
    }
}
