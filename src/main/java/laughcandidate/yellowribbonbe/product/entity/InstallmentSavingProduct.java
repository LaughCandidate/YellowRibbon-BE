package laughcandidate.yellowribbonbe.product.entity;

import jakarta.persistence.Column;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import laughcandidate.yellowribbonbe.badge.entity.Badge;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Entity
@Table(name = "INSTALLMENT_SAVING_PRODUCTS")
@DiscriminatorValue("SAVINGS")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class InstallmentSavingProduct extends Product {

    // 금리
    @Column(name = "interest_rate", precision = 5, scale = 3)
    private BigDecimal interestRate;

    // 최소 납입금
    @Column(name = "min_deposit_amount")
    private BigDecimal minDepositAmount;

    // 최대 납입금
    @Column(name = "max_deposit_amount")
    private BigDecimal maxDepositAmount;

    // 계약 기간 (개월)
    @Min(1)
    @Max(120)
    @Column(name = "contract_period_months")
    private Integer contractPeriodMonths;

    // 중도해지 이율
    @Column(name = "termination_rate", precision = 5, scale = 3)
    private BigDecimal terminationRate;

    // 우대조건
    @Min(0)
    @Max(100)
    @Column(name = "preferential_score")
    private Integer preferentialScore;

    @Builder
    public InstallmentSavingProduct(String name, String description, Badge badge, BigDecimal interestRate, BigDecimal minDepositAmount, BigDecimal maxDepositAmount, Integer contractPeriodMonths, BigDecimal terminationRate, Integer preferentialScore) {
        super(name, description, badge);
        this.interestRate = interestRate;
        this.minDepositAmount = minDepositAmount;
        this.maxDepositAmount = maxDepositAmount;
        this.contractPeriodMonths = contractPeriodMonths;
        this.terminationRate = terminationRate;
        this.preferentialScore = preferentialScore;
    }
}
