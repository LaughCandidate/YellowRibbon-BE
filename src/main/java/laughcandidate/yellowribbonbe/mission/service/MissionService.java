package laughcandidate.yellowribbonbe.mission.service;

import laughcandidate.yellowribbonbe.ai.enums.MissionResult;
import laughcandidate.yellowribbonbe.ai.util.OpenAIUtil;
import laughcandidate.yellowribbonbe.global.entity.Status;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.ImageErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.MissionErrorCode;
import laughcandidate.yellowribbonbe.image.dto.response.PresignedUrlResponse;
import laughcandidate.yellowribbonbe.image.entity.Image;
import laughcandidate.yellowribbonbe.image.repository.ImageRepository;
import laughcandidate.yellowribbonbe.image.service.ImageService;
import laughcandidate.yellowribbonbe.mission.dto.response.MissionInfoDto;
import laughcandidate.yellowribbonbe.mission.dto.response.MissionListResponse;
import laughcandidate.yellowribbonbe.mission.dto.response.MissionValidationResponse;
import laughcandidate.yellowribbonbe.mission.entity.Mission;
import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;
import laughcandidate.yellowribbonbe.mission.repository.MissionRepository;
import laughcandidate.yellowribbonbe.mission.repository.MissionSubmitRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class MissionService {

	private final OpenAIUtil openAIUtil;
	private final ImageService imageService;
	private final ImageRepository imageRepository;
	private final MissionRepository missionRepository;
	private final MissionSubmitRepository missionSubmitRepository;

	@Transactional
	public MissionValidationResponse validateMission(Long imageId) {
		Image image = imageRepository.findById(imageId)
			.orElseThrow(() -> new CustomException(ImageErrorCode.IMAGE_NOT_FOUND));

		PresignedUrlResponse presignedGetUrl = imageService.createPresignedGetUrl(imageId);

		MissionSubmit missionSubmit = image.getMissionSubmit();
		Mission mission = missionSubmit.getMission();

		String prompt = getPrompt(mission);

		MissionResult missionResult = openAIUtil.sendPrompt(prompt, presignedGetUrl.presignedUrl(), image.getType());

		if (missionResult == MissionResult.APPROVED) {
			missionSubmit.updateStatus(Status.COMPLETE);
			image.updateIsSuccess(true);
		} else if (missionResult == MissionResult.DECLINED) {
			missionSubmit.updateStatus(Status.REJECTED);
			image.updateIsSuccess(false);
			throw new CustomException(MissionErrorCode.MISSION_VALIDATION_DECLINED);
		} else {
			missionSubmit.updateStatus(Status.REJECTED);
			image.updateIsSuccess(false);
		}

		return new MissionValidationResponse(missionResult);
	}

	@Transactional(readOnly = true)
	public MissionListResponse getMissionList(Long badgeId, Long businessId) {
		List<MissionInfoDto> result = missionRepository.findMissionWithSubmitData(badgeId, businessId);
		
		if (result.isEmpty()) {
			throw new CustomException(MissionErrorCode.MISSION_NOT_FOUND);
		}

		return new MissionListResponse(result);
	}

	@Transactional(readOnly = true)
	public MissionInfoDto getMission(Long missionId, Long businessId) {
		MissionInfoDto result = missionRepository.findMissionWithSubmitDataById(missionId, businessId);
		
		if (result == null) {
			throw new CustomException(MissionErrorCode.MISSION_NOT_FOUND);
		}

		return result;
	}

	private String getPrompt(Mission mission) {
		StringBuilder prompt = new StringBuilder();
		prompt.append("다음 미션을 수행했는지 이미지를 보고 판단해주세요.\n");
		prompt.append("미션: ").append(mission.getDescription()).append("\n");
		prompt.append("‘승인’ 또는 ‘거절’만으로 답변해주세요.");

		return prompt.toString();
	}
}