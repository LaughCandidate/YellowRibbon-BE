package laughcandidate.yellowribbonbe.admin.dto.response;

import laughcandidate.yellowribbonbe.global.entity.Status;
import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record MissionSubmitResponse(
        Long missionSubmitId,
        Status status,
        String reason,
        String missionCategory,
        String missionDescription,
        String imageUrl,
        LocalDateTime submittedAt
) {}