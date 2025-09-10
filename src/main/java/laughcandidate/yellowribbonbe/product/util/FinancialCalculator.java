package laughcandidate.yellowribbonbe.product.util;

import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

@Component
public class FinancialCalculator {

    public BigDecimal calculateMonthlyPayment(BigDecimal principal, BigDecimal annualRate, int months) {
        if (principal.compareTo(BigDecimal.ZERO) <= 0 || months <= 0) {
            return BigDecimal.ZERO;
        }
        
        BigDecimal monthlyRate = annualRate.divide(BigDecimal.valueOf(1200), 10, RoundingMode.HALF_UP);
        
        if (monthlyRate.compareTo(BigDecimal.ZERO) == 0) {
            return principal.divide(BigDecimal.valueOf(months), 2, RoundingMode.HALF_UP);
        }
        
        BigDecimal onePlusRate = BigDecimal.ONE.add(monthlyRate);
        BigDecimal denominator = BigDecimal.ONE.subtract(
            onePlusRate.pow(-months, new MathContext(10))
        );
        
        return principal.multiply(monthlyRate).divide(denominator, 2, RoundingMode.HALF_UP);
    }
    

    public BigDecimal calculateTotalInterestBurden(BigDecimal monthlyPayment, int months, BigDecimal principal) {
        BigDecimal totalPayment = monthlyPayment.multiply(BigDecimal.valueOf(months));
        return totalPayment.subtract(principal);
    }
    

    public BigDecimal calculateDepositInterest(BigDecimal amount, BigDecimal annualRate, int months) {
        if (amount.compareTo(BigDecimal.ZERO) <= 0 || months <= 0) {
            return BigDecimal.ZERO;
        }
        
        BigDecimal yearFraction = BigDecimal.valueOf(months).divide(BigDecimal.valueOf(12), 4, RoundingMode.HALF_UP);
        return amount.multiply(annualRate.divide(BigDecimal.valueOf(100), 4, RoundingMode.HALF_UP))
                    .multiply(yearFraction)
                    .setScale(2, RoundingMode.HALF_UP);
    }
    

    public BigDecimal calculateSavingsMaturity(BigDecimal monthlyAmount, BigDecimal annualRate, int months) {
        if (monthlyAmount.compareTo(BigDecimal.ZERO) <= 0 || months <= 0) {
            return BigDecimal.ZERO;
        }
        
        BigDecimal monthlyRate = annualRate.divide(BigDecimal.valueOf(1200), 10, RoundingMode.HALF_UP);
        
        if (monthlyRate.compareTo(BigDecimal.ZERO) == 0) {
            return monthlyAmount.multiply(BigDecimal.valueOf(months));
        }
        
        BigDecimal onePlusRate = BigDecimal.ONE.add(monthlyRate);
        BigDecimal compound = onePlusRate.pow(months, new MathContext(10));
        BigDecimal numerator = compound.subtract(BigDecimal.ONE);
        
        return monthlyAmount.multiply(numerator)
                          .divide(monthlyRate, 10, RoundingMode.HALF_UP)
                          .multiply(onePlusRate)
                          .setScale(2, RoundingMode.HALF_UP);
    }
    

    public int calculateMonthsBetween(LocalDate startDate, LocalDate endDate) {
        if (startDate == null || endDate == null || startDate.isAfter(endDate)) {
            return 0;
        }
        
        return (int) ChronoUnit.MONTHS.between(startDate, endDate);
    }
    

    public int calculateRemainingMonths(LocalDate maturityDate) {
        return calculateMonthsBetween(LocalDate.now(), maturityDate);
    }
}
