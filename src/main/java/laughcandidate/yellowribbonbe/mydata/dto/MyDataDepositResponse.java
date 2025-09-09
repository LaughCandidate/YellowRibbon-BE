package laughcandidate.yellowribbonbe.mydata.dto;

import laughcandidate.yellowribbonbe.mydata.entity.MyDataDeposit;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public record MyDataDepositResponse(
        String productName,
        String category,
        String interestRate,
        String depositAmount,
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
