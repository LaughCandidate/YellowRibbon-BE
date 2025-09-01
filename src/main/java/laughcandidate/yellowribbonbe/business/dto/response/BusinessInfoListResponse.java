package laughcandidate.yellowribbonbe.business.dto.response;

import java.util.List;

public record BusinessInfoListResponse(
	List<BusinessInfoResponse> businesses
) {
}