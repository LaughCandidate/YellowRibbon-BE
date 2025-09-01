package laughcandidate.yellowribbonbe.business.dto.response;

import java.time.LocalDate;

public record BusinessInfoResponse(
    Long businessId,
    String businessNo,
    String ownerName,
    LocalDate startDate,
    String businessName
) {
}