package laughcandidate.yellowribbonbe.mission.service;

import java.util.Arrays;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import laughcandidate.yellowribbonbe.ai.enums.MissionResult;
import laughcandidate.yellowribbonbe.ai.util.OpenAIUtil;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.MissionErrorCode;
import laughcandidate.yellowribbonbe.mission.dto.response.MissionValidationResponse;
import laughcandidate.yellowribbonbe.mission.entity.Mission;
import laughcandidate.yellowribbonbe.mission.repository.MissionRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class MissionService {

	private final OpenAIUtil openAIUtil;
	private final MissionRepository missionRepository;
	
	private static final long MAX_FILE_SIZE = 10 * 1024 * 1024L; // 10MB
	private static final List<String> ALLOWED_TYPES = Arrays.asList("image/jpeg", "image/png", "image/jpg");

	public MissionValidationResponse validateMission(Long missionId, MultipartFile image) {
		validateImageFile(image);

		Mission mission = missionRepository.findById(missionId)
			.orElseThrow(() -> new CustomException(MissionErrorCode.MISSION_NOT_FOUND));

		String prompt = getPrompt(mission);

		MissionResult missionResult = openAIUtil.sendPrompt(prompt, image);

		return new MissionValidationResponse(missionResult);
	}
	
	private void validateImageFile(MultipartFile image) {
		if (image == null || image.isEmpty()) {
			throw new CustomException(MissionErrorCode.INVALID_IMAGE_FILE);
		}
		
		if (image.getSize() > MAX_FILE_SIZE) {
			throw new CustomException(MissionErrorCode.FILE_SIZE_EXCEEDED);
		}
		
		String contentType = image.getContentType();
		if (contentType == null || !ALLOWED_TYPES.contains(contentType)) {
			throw new CustomException(MissionErrorCode.NOT_IMAGE_FILE);
		}
	}

	private String getPrompt(Mission mission) {
		StringBuilder prompt = new StringBuilder();
		prompt.append("다음 미션을 수행했는지 이미지를 보고 판단해주세요.\n");
		prompt.append("미션: ").append(mission.getDescription()).append("\n");
		prompt.append("카테고리: ").append(mission.getCategory()).append("\n");
		prompt.append("‘승인’ 또는 ‘거절’만으로 답변해주세요.");

		return prompt.toString();
	}
}