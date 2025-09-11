package laughcandidate.yellowribbonbe.codef.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CodefAccountRegisterRequest {

    @NotBlank(message = "계정 ID는 필수입니다")
    private String accountId;

    @NotBlank(message = "비밀번호는 필수입니다")
    private String password;

    @NotBlank(message = "기관코드는 필수입니다")
    private String organization;

    private String accountType;
    
    private String birthDate;
    
    private String phoneNo;
    
    private String identity;
    
    private String userName;
}