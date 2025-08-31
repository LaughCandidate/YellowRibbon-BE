package laughcandidate.yellowribbonbe.business.service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;

import org.springframework.stereotype.Service;

import jakarta.transaction.Transactional;
import laughcandidate.yellowribbonbe.auth.jwt.TokenProvider;
import laughcandidate.yellowribbonbe.auth.jwt.dto.UserTokenResponse;
import laughcandidate.yellowribbonbe.business.dto.BusinessInfo;
import laughcandidate.yellowribbonbe.business.dto.request.BusinessValidationRequest;
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

	public ConnectResponse connectBusinessRequired(String businessNo, String ownerName, String startDate,
		String businessName,
		boolean isLast, Long userId) {
		validateBusiness(businessNo, ownerName, startDate);

		User user = userRepository.findById(userId)
			.orElseThrow(() -> new CustomException(AuthErrorCode.USER_NOT_FOUND));

		LocalDate parsedStartDate = LocalDate.parse(startDate, DateTimeFormatter.ofPattern("yyyyMMdd"));

		saveBusiness(businessNo, businessName, ownerName, parsedStartDate, user);

		if (isLast) {
			user.updateRole();
			UserTokenResponse token = tokenProvider.createLoginToken(user.getUid(), userId, Role.USER.getRole());
			return new ConnectResponse(isLast, token.accessToken(), token.refreshToken());
		}

		return new ConnectResponse(isLast, null, null);
	}

	public void connectBusinessOptional(String businessNo, String ownerName, String startDate, String businessName,
		Long userId) {
		validateBusiness(businessNo, ownerName, startDate);

		User user = userRepository.findById(userId)
			.orElseThrow(() -> new CustomException(AuthErrorCode.USER_NOT_FOUND));

		LocalDate parsedStartDate = LocalDate.parse(startDate, DateTimeFormatter.ofPattern("yyyyMMdd"));

		saveBusiness(businessNo, businessName, ownerName, parsedStartDate, user);
	}

	@Transactional
	protected void saveBusiness(String businessNo, String businessName, String ownerName, LocalDate startDate,
		User user) {
		Business business = Business.builder()
			.businessNo(businessNo)
			.businessName(businessName)
			.ownerName(ownerName)
			.startDate(startDate)
			.user(user)
			.build();

		businessRepository.save(business);
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
