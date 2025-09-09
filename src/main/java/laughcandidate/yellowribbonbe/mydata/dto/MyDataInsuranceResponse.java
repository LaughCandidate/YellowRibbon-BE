package laughcandidate.yellowribbonbe.mydata.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import laughcandidate.yellowribbonbe.mydata.entity.MyDataInsurance;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;

import java.math.BigDecimal;

@Schema(name = "MyDataInsuranceResponse: 나의 보유 보험 응답 DTO")
public record MyDataInsuranceResponse(
        @Schema(description = "보험 상품명", example = "삼성화재 소상공인 종합보험")
        String productName,
        @Schema(description = "상품 카테고리", example = "보험")
        String category,
        @Schema(description = "월 보험료", example = "50,000원")
        String monthlyPremium,
        @Schema(description = "보장 종류", example = "소상공인종합보험")
        String coverageType,
        @Schema(description = "보험 기간", example = "1년")
        String coveragePeriod,
        @Schema(description = "보장 금액", example = "30,000만원")
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
