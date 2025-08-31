package laughcandidate.yellowribbonbe.business.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import laughcandidate.yellowribbonbe.business.dto.request.BusinessValidationRequest;
import laughcandidate.yellowribbonbe.business.dto.response.BusinessValidationResponse;

@FeignClient(name = "businessValidationClient", url = "${open-api.url}")
public interface BusinessValidationClient {
	
	@PostMapping
	BusinessValidationResponse validateBusiness(
		@RequestParam String serviceKey,
		@RequestBody BusinessValidationRequest request
	);
}