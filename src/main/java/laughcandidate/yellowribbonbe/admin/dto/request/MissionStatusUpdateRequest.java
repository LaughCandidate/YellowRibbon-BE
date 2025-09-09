package laughcandidate.yellowribbonbe.admin.dto.request;

import laughcandidate.yellowribbonbe.global.entity.Status;
import lombok.Builder;

import jakarta.validation.constraints.NotNull;

@Builder
public record MissionStatusUpdateRequest(
        @NotNull(message = "상태는 필수입니다")
        Status status,
        
        String reason
) {
}