package laughcandidate.yellowribbonbe.admin.dto.response;

import laughcandidate.yellowribbonbe.global.entity.Status;
import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;
import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record MissionSubmitResponse(
        Long missionSubmitId,
        Status status,
        String reason,
        String missionCategory,
        String missionDescription,
        Long imageId,
        String imageUuid,
        LocalDateTime submittedAt
) {
    public static MissionSubmitResponse from(MissionSubmit missionSubmit, Long imageId, String imageUuid) {
        return MissionSubmitResponse.builder()
                .missionSubmitId(missionSubmit.getId())
                .status(missionSubmit.getStatus())
                .reason(missionSubmit.getReason())
                .missionCategory(missionSubmit.getMission().getCategory())
                .missionDescription(missionSubmit.getMission().getDescription())
                .imageId(imageId)
                .imageUuid(imageUuid)
                .submittedAt(missionSubmit.getCreatedAt())
                .build();
    }
}