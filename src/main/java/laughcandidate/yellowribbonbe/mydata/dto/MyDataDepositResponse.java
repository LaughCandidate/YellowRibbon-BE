package laughcandidate.yellowribbonbe.mydata.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import laughcandidate.yellowribbonbe.mydata.entity.MyDataDeposit;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@Schema(name = "MyDataDepositResponse: 나의 보유 예금 응답 DTO")
public record MyDataDepositResponse(
        @Schema(description = "예금 상품명", example = "KB기업자유예금통장")
        String productName,
        @Schema(description = "상품 카테고리", example = "예금")
        String category,
        @Schema(description = "적용 금리", example = "3.50%")
        String interestRate,
        @Schema(description = "예치 금액", example = "1,500만원")
        String depositAmount,
        @Schema(description = "예치 기간", example = "2024.01.15 ~ 2025.01.15")
        String depositPeriod
) implements MyDataResponse {

    public static MyDataDepositResponse from(MyDataDeposit deposit) {
        return new MyDataDepositResponse(
                deposit.getProductName(),
                deposit.getCategory().getDescription(),
                String.format("%.2f%%", deposit.getInterestRate()),
                formatToTenThousand(deposit.getAmount()),
                formatDepositPeriod(deposit.getStartDate(), deposit.getMaturityDate())
        );
    }

    private static String formatToTenThousand(BigDecimal amount) {
        if (amount == null) return "0만원";
        return String.format("%,d만원", amount.longValue() / 10000);
    }

    private static String formatDepositPeriod(LocalDate startDate, LocalDate endDate) {
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
