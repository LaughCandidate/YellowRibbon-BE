package laughcandidate.yellowribbonbe.product.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import laughcandidate.yellowribbonbe.badge.entity.Badge;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Entity
@Table(name = "INSURANCE_PRODUCTS")
@DiscriminatorValue("INSURANCE")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class InsuranceProduct extends Product {

    // 보험 기간(단위: 년)
    @Column(name = "ins_term")
    private Integer insTerm;

    // 월 납입 보험료
    @Column(name = "premium")
    private BigDecimal premium;

    // 보장 종류
    @Enumerated(EnumType.STRING)
    @Column(name = "coverage_type")
    private CoverageType coverageType;

    // 보장 금액
    @Column(name = "coverage_amount")
    private BigDecimal coverageAmount;

    // 우대 조건
    @Min(0)
    @Max(100)
    @Column(name = "preferential_score")
    private Integer preferentialScore;

    @Builder
    public InsuranceProduct(String name, String description, Badge badge, Integer insTerm, BigDecimal premium, CoverageType coverageType, BigDecimal coverageAmount, Integer preferentialScore) {
        super(name, description, badge);
        this.insTerm = insTerm;
        this.premium = premium;
        this.coverageType = coverageType;
        this.coverageAmount = coverageAmount;
        this.preferentialScore = preferentialScore;
    }
}