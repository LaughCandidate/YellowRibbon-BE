package laughcandidate.yellowribbonbe.business.service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import laughcandidate.yellowribbonbe.auth.jwt.TokenProvider;
import laughcandidate.yellowribbonbe.auth.jwt.dto.UserTokenResponse;
import laughcandidate.yellowribbonbe.business.dto.BusinessInfo;
import laughcandidate.yellowribbonbe.business.dto.request.BusinessValidationRequest;
import laughcandidate.yellowribbonbe.business.dto.response.BusinessInfoListResponse;
import laughcandidate.yellowribbonbe.business.dto.response.BusinessInfoResponse;
import laughcandidate.yellowribbonbe.business.dto.response.BusinessValidationResponse;
import laughcandidate.yellowribbonbe.business.dto.response.ConnectResponse;
import laughcandidate.yellowribbonbe.business.entity.Business;
import laughcandidate.yellowribbonbe.business.repository.BusinessRepository;
import laughcandidate.yellowribbonbe.business.util.OpenApiUtil;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AuthErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.BusinessErrorCode;
import laughcandidate.yellowribbonbe.user.entity.Role;
import laughcandidate.yellowribbonbe.user.entity.User;
import laughcandidate.yellowribbonbe.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class BusinessService {

	private static final String VERIFIED = "01";

	private final OpenApiUtil openApiUtil;
	private final BusinessRepository businessRepository;
	private final UserRepository userRepository;
	private final TokenProvider tokenProvider;

	@Transactional
	public ConnectResponse connectBusiness(String businessNo, String ownerName, String startDate,
		String businessName,
		Long userId) {
		validateBusiness(businessNo, ownerName, startDate);

		User user = userRepository.findById(userId)
			.orElseThrow(() -> new CustomException(AuthErrorCode.USER_NOT_FOUND));

		LocalDate parsedStartDate = LocalDate.parse(startDate, DateTimeFormatter.ofPattern("yyyyMMdd"));

		Business business = saveBusiness(businessNo, businessName, ownerName, parsedStartDate, user);

		if (user.getRole() == Role.ROLE_TEMP_USER) {
			user.updateRole();
		}

		UserTokenResponse token = tokenProvider.createLoginToken(user.getUid(), userId, Role.ROLE_USER.getRole(), business.getId());

		return new ConnectResponse(token.accessToken(), token.refreshToken(), user.getRole(), business.getId());
	}

	@Transactional(readOnly = true)
	public BusinessInfoListResponse getBusinessesInfo(Long userId) {
		List<Business> businesses = businessRepository.findByUserId(userId);
		List<BusinessInfoResponse> responses = new ArrayList<>();
		
		for (Business business : businesses) {
			responses.add(new BusinessInfoResponse(
				business.getId(),
				business.getBusinessNo(),
				business.getOwnerName(),
				business.getStartDate(),
				business.getBusinessName()
			));
		}
		
		return new BusinessInfoListResponse(responses);
	}

	@Transactional
	protected Business saveBusiness(String businessNo, String businessName, String ownerName, LocalDate startDate,
		User user) {
		Business business = Business.builder()
			.businessNo(businessNo)
			.businessName(businessName)
			.ownerName(ownerName)
			.startDate(startDate)
			.user(user)
			.build();

		businessRepository.save(business);

		return business;
	}

	private void validateBusiness(String businessNo, String ownerName, String startDate) {
		if (businessRepository.existsByBusinessNo(businessNo)) {
			throw new CustomException(BusinessErrorCode.BUSINESS_NO_DUPLICATED);
		}

		BusinessInfo businessInfo = new BusinessInfo(businessNo, ownerName, startDate);
		BusinessValidationRequest request = new BusinessValidationRequest(List.of(businessInfo));

		BusinessValidationResponse response = openApiUtil.validateBusiness(request);

		if (response.data().isEmpty() || !VERIFIED.equals(response.data().get(0).valid())) {
			throw new CustomException(BusinessErrorCode.BUSINESS_NOT_FOUND);
		}
	}
}
