package laughcandidate.yellowribbonbe.product.dto;

import lombok.Builder;
import lombok.Getter;

import java.math.BigDecimal;

@Getter
@Builder
public class CalculatedMetrics {
    //금리
    private BigDecimal interestRate;
    
    // 대출용
    private BigDecimal monthlyPayment;
    private BigDecimal totalInterestBurden;
    private BigDecimal prepaymentFee;
    private BigDecimal loanLimit;
    private int remainingMonths;
    
    // 예금용  
    private BigDecimal maturityInterest;
    private BigDecimal maturityAmount;
    private BigDecimal depositAmount;
    private BigDecimal minAmount;
    private BigDecimal terminationRate;
    private Integer preferential;
    private int depositMonths;
    
    // 적금용
    private BigDecimal totalDeposit;
    private BigDecimal savingsMaturityAmount;
    private BigDecimal savingsMaturityInterest;
    private BigDecimal monthlyAmount;
    private BigDecimal maxAmount;
    private int savingsMonths;
}
