package laughcandidate.yellowribbonbe.business.dto.request;

import java.util.List;

import laughcandidate.yellowribbonbe.business.dto.BusinessInfo;

public record BusinessValidationRequest(
	List<BusinessInfo> businesses
) {
}