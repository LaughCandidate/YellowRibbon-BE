package laughcandidate.yellowribbonbe.product.entity;

import jakarta.persistence.*;
import laughcandidate.yellowribbonbe.badge.entity.Badge;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;


@Entity
@Table(name = "LOAN_PRODUCTS")
@DiscriminatorValue("LOAN")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class LoanProduct extends Product {

    // 금리
    @Column(name = "interest_rate", precision = 5, scale = 3)
    private BigDecimal interestRate;

    // 대출 한도
    @Column(name = "loan_limit")
    private BigDecimal loanLimit;

    // 상환 방식
    @Enumerated(EnumType.STRING)
    @Column(name = "repayment_method")
    private RepaymentMethod repaymentMethod;

    // 중도상환 수수료율
    @Column(name = "prepayment_fee_rate", precision = 5, scale = 3)
    private BigDecimal prepaymentFeeRate;

    @Builder
    public LoanProduct(String name, String description, Badge badge, BigDecimal interestRate, BigDecimal loanLimit, RepaymentMethod repaymentMethod, BigDecimal prepaymentFeeRate) {
        super(name, description, badge);
        this.interestRate = interestRate;
        this.loanLimit = loanLimit;
        this.repaymentMethod = repaymentMethod;
        this.prepaymentFeeRate = prepaymentFeeRate;
    }
}