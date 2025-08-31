package laughcandidate.yellowribbonbe.business.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import laughcandidate.yellowribbonbe.business.client.BusinessValidationClient;
import laughcandidate.yellowribbonbe.business.dto.request.BusinessValidationRequest;
import laughcandidate.yellowribbonbe.business.dto.response.BusinessValidationResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class OpenApiUtil {

	@Value("${open-api.key}")
	private String serviceKey;
	
	private final BusinessValidationClient businessValidationClient;

	public BusinessValidationResponse validateBusiness(BusinessValidationRequest request) {
		return businessValidationClient.validateBusiness(serviceKey, request);
	}
}
