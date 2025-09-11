package laughcandidate.yellowribbonbe.codef.service;

import io.codef.api.EasyCodef;
import io.codef.api.EasyCodefServiceType;
import laughcandidate.yellowribbonbe.codef.config.CodefConfig;
import laughcandidate.yellowribbonbe.codef.dto.request.CodefAccountRegisterRequest;
import laughcandidate.yellowribbonbe.codef.dto.response.CodefAccountRegisterResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class CodefAccountService {

    private final EasyCodef easyCodef;
    private final CodefConfig codefConfig;

    public CodefAccountRegisterResponse registerAccount(CodefAccountRegisterRequest request, boolean isProduction) {
        try {
            log.info("Account registration request received for organization: {}", request.getOrganization());
            
            HashMap<String, Object> accountMap = buildAccountMap(request);
            EasyCodefServiceType serviceType = codefConfig.getServiceType(isProduction);
            String result = easyCodef.createAccount(serviceType, accountMap);
            
            log.info("Codef account registration result: {}", result);
            
            CodefAccountRegisterResponse response = parseResponse(result, request);
            
            if (response.isSuccess()) {
                log.info("Account registration successful for accountId: {}", request.getAccountId());
            } else {
                log.warn("Account registration failed for accountId: {}, error: {}", 
                        request.getAccountId(), response.getMessage());
            }
            
            return response;
            
        } catch (Exception e) {
            log.error("Failed to register account with Codef", e);
            return buildErrorResponse(request, "CF-00999", "서버 오류가 발생했습니다: " + e.getMessage());
        }
    }

    private HashMap<String, Object> buildAccountMap(CodefAccountRegisterRequest request) {
        HashMap<String, Object> accountMap = new HashMap<>();
        
        accountMap.put("accountId", request.getAccountId());
        accountMap.put("accountPassword", request.getPassword());
        accountMap.put("organization", request.getOrganization());
        
        if (request.getAccountType() != null) {
            accountMap.put("accountType", request.getAccountType());
        }
        if (request.getBirthDate() != null) {
            accountMap.put("birthDate", request.getBirthDate());
        }
        if (request.getPhoneNo() != null) {
            accountMap.put("phoneNo", request.getPhoneNo());
        }
        if (request.getIdentity() != null) {
            accountMap.put("identity", request.getIdentity());
        }
        if (request.getUserName() != null) {
            accountMap.put("userName", request.getUserName());
        }
        
        return accountMap;
    }

    private CodefAccountRegisterResponse buildErrorResponse(CodefAccountRegisterRequest request, String errorCode, String message) {
        return CodefAccountRegisterResponse.builder()
                .success(false)
                .result(errorCode)
                .message(message)
                .accountId(request.getAccountId())
                .organization(request.getOrganization())
                .build();
    }

    private CodefAccountRegisterResponse parseResponse(String result, CodefAccountRegisterRequest request) {
        try {
            if (result != null && result.contains("\"result\":\"CF-00000\"")) {
                String connectedId = extractConnectedId(result);
                
                return CodefAccountRegisterResponse.builder()
                        .success(true)
                        .result("CF-00000")
                        .message("계정이 성공적으로 등록되었습니다.")
                        .connectedId(connectedId)
                        .accountId(request.getAccountId())
                        .organization(request.getOrganization())
                        .registerDate(java.time.LocalDateTime.now().toString())
                        .build();
            } else {
                String errorCode = extractErrorCode(result);
                String errorMessage = extractErrorMessage(result);
                
                return CodefAccountRegisterResponse.builder()
                        .success(false)
                        .result(errorCode)
                        .message(errorMessage)
                        .accountId(request.getAccountId())
                        .organization(request.getOrganization())
                        .build();
            }
        } catch (Exception e) {
            log.error("Failed to parse Codef response", e);
            return CodefAccountRegisterResponse.builder()
                    .success(false)
                    .result("CF-00999")
                    .message("응답 파싱 중 오류가 발생했습니다.")
                    .build();
        }
    }

    private String extractConnectedId(String result) {
        try {
            int startIndex = result.indexOf("\"connectedId\":\"") + 15;
            int endIndex = result.indexOf("\"", startIndex);
            return result.substring(startIndex, endIndex);
        } catch (Exception e) {
            log.warn("Failed to extract connectedId from response", e);
            return null;
        }
    }

    private String extractErrorCode(String result) {
        try {
            int startIndex = result.indexOf("\"result\":\"") + 10;
            int endIndex = result.indexOf("\"", startIndex);
            return result.substring(startIndex, endIndex);
        } catch (Exception e) {
            log.warn("Failed to extract error code from response", e);
            return "CF-00999";
        }
    }

    private String extractErrorMessage(String result) {
        try {
            int startIndex = result.indexOf("\"message\":\"") + 11;
            int endIndex = result.indexOf("\"", startIndex);
            return result.substring(startIndex, endIndex);
        } catch (Exception e) {
            log.warn("Failed to extract error message from response", e);
            return "알 수 없는 오류가 발생했습니다.";
        }
    }
}