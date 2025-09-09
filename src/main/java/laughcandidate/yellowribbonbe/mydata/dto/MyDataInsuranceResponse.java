package laughcandidate.yellowribbonbe.mydata.dto;

import laughcandidate.yellowribbonbe.mydata.entity.MyDataInsurance;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;

import java.math.BigDecimal;

public record MyDataInsuranceResponse(
        String productName,
        String category,
        String monthlyPremium,
        String coverageType,
        String coveragePeriod,
        String coverageAmount
) implements MyDataResponse {

    public static MyDataInsuranceResponse from(MyDataInsurance insurance) {
        return new MyDataInsuranceResponse(
                insurance.getProductName(),
                insurance.getCategory().getDescription(),
                formatPremium(insurance.getPremium()),
                insurance.getCoverageType(),
                formatCoveragePeriod(insurance.getInsTerm()),
                formatToTenThousand(insurance.getCoverage())
        );
    }

    private static String formatPremium(BigDecimal premium) {
        if (premium == null) return "0원";
        return String.format("%,d원", premium.longValue());
    }

    private static String formatCoveragePeriod(Integer insTerm) {
        if (insTerm == null) return "";
        return insTerm + "년";
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
