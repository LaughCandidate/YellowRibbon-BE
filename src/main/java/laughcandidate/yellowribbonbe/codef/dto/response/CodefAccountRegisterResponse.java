package laughcandidate.yellowribbonbe.codef.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CodefAccountRegisterResponse {

    private String result;
    
    private String message;
    
    private String connectedId;
    
    private String accountId;
    
    private String organization;
    
    private String registerDate;
    
    private boolean success;
}