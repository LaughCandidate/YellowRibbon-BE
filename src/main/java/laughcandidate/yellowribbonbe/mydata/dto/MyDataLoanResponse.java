package laughcandidate.yellowribbonbe.mydata.dto;

import laughcandidate.yellowribbonbe.mydata.entity.MyDataLoan;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeFormatter;

public record MyDataLoanResponse(
        String productName,
        String category,
        String interestRate,
        String repayMethod,
        String totalLoanAmount,
        String monthlyRepayment,
        String remainingBalance,
        String loanPeriod
) implements MyDataResponse {

    public static MyDataLoanResponse from(MyDataLoan loan) {
        return new MyDataLoanResponse(
                loan.getProductName(),
                loan.getCategory().getDescription(),
                String.format("%.2f%%", loan.getInterestRate()),
                loan.getRepayMethod(),
                formatToTenThousand(loan.getPrincipal()),
                calculateMonthlyRepayment(loan),
                formatToTenThousand(loan.getRemainPrincipal()),
                formatLoanPeriod(loan.getExecDate(), loan.getMaturityDate())
        );
    }

    private static String formatToTenThousand(BigDecimal amount) {
        if (amount == null) return "0만원";
        return String.format("%,d만원", amount.longValue() / 10000);
    }

    private static String calculateMonthlyRepayment(MyDataLoan loan) {
        // 대출잔액 × 월이율 ÷ (1 - (1+월이율)^(-남은기간))
        // 월이율 = 금리 ÷ 12

        BigDecimal remainingPrincipal = loan.getRemainPrincipal();
        if (remainingPrincipal == null || remainingPrincipal.compareTo(BigDecimal.ZERO) == 0) {
            return "0만원";
        }


        BigDecimal monthlyRate = loan.getInterestRate()
                .divide(BigDecimal.valueOf(12), 10, RoundingMode.HALF_UP)
                .divide(BigDecimal.valueOf(100), 10, RoundingMode.HALF_UP);

        if (monthlyRate.compareTo(BigDecimal.ZERO) == 0) {
            int remainingMonths = calculateRemainingMonths(loan.getExecDate(), loan.getMaturityDate());
            if (remainingMonths <= 0) return "0만원";
            BigDecimal monthlyAmount = remainingPrincipal.divide(BigDecimal.valueOf(remainingMonths), 0, RoundingMode.HALF_UP);
            return formatToTenThousand(monthlyAmount);
        }


        int remainingMonths = calculateRemainingMonths(loan.getExecDate(), loan.getMaturityDate());
        if (remainingMonths <= 0) return "0만원";

        // (1 + 월이율)^(-남은기간)
        BigDecimal onePlusRate = BigDecimal.ONE.add(monthlyRate);
        BigDecimal powerResult = BigDecimal.ONE.divide(onePlusRate.pow(remainingMonths), 10, RoundingMode.HALF_UP);

        // 1 - (1+월이율)^(-남은기간)
        BigDecimal denominator = BigDecimal.ONE.subtract(powerResult);

        // 대출잔액 × 월이율 ÷ (1 - (1+월이율)^(-남은기간))
        BigDecimal monthlyPayment = remainingPrincipal.multiply(monthlyRate).divide(denominator, 0, RoundingMode.HALF_UP);

        return formatToTenThousand(monthlyPayment);
    }

    private static int calculateRemainingMonths(LocalDate startDate, LocalDate endDate) {
        if (startDate == null || endDate == null) return 24;
        LocalDate now = LocalDate.now();

        if (now.isAfter(endDate)) return 0;
        if (now.isBefore(startDate)) now = startDate;

        Period period = Period.between(now, endDate);
        return period.getYears() * 12 + period.getMonths();
    }

    private static String formatLoanPeriod(LocalDate startDate, LocalDate endDate) {
        if (startDate == null || endDate == null) return "";
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy.MM.dd");
        return String.format("%s ~ %s", startDate.format(formatter), endDate.format(formatter));
    }

    @Override
    public String getCategory() {
        return category;
    }

    @Override
    public String getProductName() {
        return productName;
    }
}
