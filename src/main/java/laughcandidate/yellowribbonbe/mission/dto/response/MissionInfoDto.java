package laughcandidate.yellowribbonbe.mission.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import laughcandidate.yellowribbonbe.global.entity.Status;
import laughcandidate.yellowribbonbe.badge.entity.Category;

@Schema(description = "미션 정보")
public record MissionInfoDto(
    @Schema(description = "거절 사유")
    String reason,
    
    @Schema(description = "미션 상태")
    Status status,
    
    @Schema(description = "미션 설명")
    String description,
    
    @Schema(description = "미션 ID")
    Long missionId,
    
    @Schema(description = "배지 카테고리")
    Category category,

    @Schema(description = "미션 시도 여부")
    Boolean tried
) {}