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
@Table(name = "MYDATA_INSTALLMENT_SAVING")
@DiscriminatorValue("SAVINGS")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MyDataSavings extends MyData {

    @Column(name = "interest_rate")
    private BigDecimal interestRate;

    @Column(name = "min_amount")
    private BigDecimal minAmount;

    @Column(name = "max_amount")
    private BigDecimal maxAmount;

    @Column(name = "termination_rate")
    private BigDecimal terminationRate;

    @Column(name = "preferential")
    private Integer preferential;

    @Column(name = "monthly_pay")
    private BigDecimal monthlyPay;

    @Column(name = "start_date")
    private LocalDate startDate;

    @Column(name = "maturity_date")
    private LocalDate maturityDate;

    @Builder
    public MyDataSavings(User user, String productName, BigDecimal interestRate, BigDecimal minAmount,
                         BigDecimal maxAmount, BigDecimal terminationRate, Integer preferential,
                         BigDecimal monthlyPay, LocalDate startDate, LocalDate maturityDate) {
        super(user, productName);
        this.interestRate = interestRate;
        this.minAmount = minAmount;
        this.maxAmount = maxAmount;
        this.terminationRate = terminationRate;
        this.preferential = preferential;
        this.monthlyPay = monthlyPay;
        this.startDate = startDate;
        this.maturityDate = maturityDate;
    }

    @Override
    public ProductCategory getCategory() {
        return ProductCategory.SAVINGS;
    }
}
