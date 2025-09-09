package laughcandidate.yellowribbonbe.mydata.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import laughcandidate.yellowribbonbe.mydata.entity.MyDataSavings;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.time.Period;

@Schema(name = "MyDataSavingsResponse: 나의 보유 적금 응답 DTO")
public record MyDataSavingsResponse(
        @Schema(description = "적금 상품명", example = "KB사업자 세금적금")
        String productName,
        @Schema(description = "상품 카테고리", example = "적금")
        String category,
        @Schema(description = "적용 금리", example = "3.80%")
        String interestRate,
        @Schema(description = "총 납입액", example = "1,200만원")
        String totalPaymentAmount,
        @Schema(description = "납입 기간", example = "24개월")
        String paymentPeriodMonths,
        @Schema(description = "월 납입액", example = "50만원")
        String monthlyPayment,
        @Schema(description = "만기 예상 수령액", example = "1,280만원")
        String maturityAmount
) implements MyDataResponse {

    public static MyDataSavingsResponse from(MyDataSavings savings) {
        int periodInMonths = calculatePaymentPeriodInMonths(savings.getStartDate(), savings.getMaturityDate());
        
        return new MyDataSavingsResponse(
                savings.getProductName(),
                savings.getCategory().getDescription(),
                String.format("%.2f%%", savings.getInterestRate()),
                calculateTotalPaymentAmount(savings.getMonthlyPay(), periodInMonths),
                periodInMonths + "개월",
                formatToTenThousand(savings.getMonthlyPay()),
                calculateMaturityAmount(savings.getMonthlyPay(), savings.getInterestRate(), periodInMonths)
        );
    }

    private static int calculatePaymentPeriodInMonths(LocalDate startDate, LocalDate endDate) {
        if (startDate == null || endDate == null) return 0;
        Period period = Period.between(startDate, endDate);
        return period.getYears() * 12 + period.getMonths();
    }

    private static String calculateTotalPaymentAmount(BigDecimal monthlyPay, int months) {
        if (monthlyPay == null) return "0만원";
        BigDecimal total = monthlyPay.multiply(BigDecimal.valueOf(months));
        return formatToTenThousand(total);
    }

    private static String calculateMaturityAmount(BigDecimal monthlyPay, BigDecimal yearlyRate, int months) {
        if (monthlyPay == null || yearlyRate == null || months == 0) return "0만원";
        
        // 월이율 = 연이율 ÷ 12
        BigDecimal monthlyRate = yearlyRate.divide(BigDecimal.valueOf(12), 10, RoundingMode.HALF_UP)
                                           .divide(BigDecimal.valueOf(100), 10, RoundingMode.HALF_UP);
        
        if (monthlyRate.compareTo(BigDecimal.ZERO) == 0) {
            return calculateTotalPaymentAmount(monthlyPay, months);
        }
        
        // 월납입액 × ( (1 + 월이율)^(납입기간) – 1 ) ÷ 월이율 × (1 + 월이율)
        BigDecimal onePlusRate = BigDecimal.ONE.add(monthlyRate);
        BigDecimal powerResult = onePlusRate.pow(months);
        
        BigDecimal numerator = powerResult.subtract(BigDecimal.ONE);
        BigDecimal fraction = numerator.divide(monthlyRate, 10, RoundingMode.HALF_UP);
        BigDecimal maturityAmount = monthlyPay.multiply(fraction).multiply(onePlusRate);
        
        return formatToTenThousand(maturityAmount);
    }

    private static String formatToTenThousand(BigDecimal amount) {
        if (amount == null) return "0만원";
        return String.format("%,d만원", amount.longValue() / 10000);
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
