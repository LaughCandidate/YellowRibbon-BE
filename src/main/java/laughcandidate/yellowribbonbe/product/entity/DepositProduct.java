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
@Table(name = "DEPOSIT_PRODUCTS")
@DiscriminatorValue("DEPOSIT")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class DepositProduct extends Product {

    // 금리
    @Column(name = "interest_rate", precision = 5, scale = 3)
    private BigDecimal interestRate;

    // 최소 예치금
    @Column(name = "min_amount")
    private BigDecimal minAmount;

    // 중도해지 이율
    @Column(name = "termination_rate", precision = 5, scale = 3)
    private BigDecimal terminationRate;

    // 우대조건
    @Min(0)
    @Max(100)
    @Column(name = "preferential_score")
    private Integer preferentialScore;

    @Builder
    public DepositProduct(String name, String description, Badge badge, BigDecimal interestRate, BigDecimal minAmount, BigDecimal terminationRate, Integer preferentialScore) {
        super(name, description, badge);
        this.interestRate = interestRate;
        this.minAmount = minAmount;
        this.terminationRate = terminationRate;
        this.preferentialScore = preferentialScore;
    }
}