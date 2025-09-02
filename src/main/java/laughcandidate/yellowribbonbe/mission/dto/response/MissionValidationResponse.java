package laughcandidate.yellowribbonbe.mission.dto.response;

import laughcandidate.yellowribbonbe.ai.enums.MissionResult;

public record MissionValidationResponse(
	MissionResult result
) {
}