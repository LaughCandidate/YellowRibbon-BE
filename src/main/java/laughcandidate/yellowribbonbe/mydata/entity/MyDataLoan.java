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
@Table(name = "MYDATA_LOAN")
@DiscriminatorValue("LOAN")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MyDataLoan extends MyData {

    @Column(name = "interest_rate")
    private BigDecimal interestRate;

    @Column(name = "loan_limit")
    private BigDecimal loanLimit;

    @Column(name = "repay_method")
    private String repayMethod;

    @Column(name = "prepayment_fee_rate")
    private BigDecimal prepaymentFeeRate;

    @Column(name = "principal")
    private BigDecimal principal;

    @Column(name = "remain_principal")
    private BigDecimal remainPrincipal;

    @Column(name = "exec_date")
    private LocalDate execDate;

    @Column(name = "maturity_date")
    private LocalDate maturityDate;

    @Builder
    public MyDataLoan(User user, String productName, BigDecimal interestRate, BigDecimal loanLimit,
                      String repayMethod, BigDecimal prepaymentFeeRate, BigDecimal principal,
                      BigDecimal remainPrincipal, LocalDate execDate, LocalDate maturityDate) {
        super(user, productName);
        this.interestRate = interestRate;
        this.loanLimit = loanLimit;
        this.repayMethod = repayMethod;
        this.prepaymentFeeRate = prepaymentFeeRate;
        this.principal = principal;
        this.remainPrincipal = remainPrincipal;
        this.execDate = execDate;
        this.maturityDate = maturityDate;
    }

    @Override
    public ProductCategory getCategory() {
        return ProductCategory.LOAN;
    }
}
