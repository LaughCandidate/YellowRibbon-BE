package laughcandidate.yellowribbonbe.business.dto.response;

import java.util.List;

import laughcandidate.yellowribbonbe.business.dto.BusinessValidationData;

public record BusinessValidationResponse(
	int request_cnt,
	int valid_cnt,
	String status_code,
	List<BusinessValidationData> data
) {
}