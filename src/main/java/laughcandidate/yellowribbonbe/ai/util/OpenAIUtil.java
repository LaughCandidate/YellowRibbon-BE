package laughcandidate.yellowribbonbe.ai.util;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.stereotype.Component;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.multipart.MultipartFile;

import laughcandidate.yellowribbonbe.ai.enums.MissionResult;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.MissionErrorCode;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class OpenAIUtil {

	private final ChatClient chatClient;

	public MissionResult sendPrompt(String prompt, MultipartFile image) {
		validateInput(prompt);

		try {
			ByteArrayResource imageResource = new ByteArrayResource(image.getBytes());
			MimeType mimeType = MimeTypeUtils.parseMimeType(image.getContentType());

			var chatResponse = chatClient.prompt()
				.user(userSpec -> userSpec
					.text(prompt)
					.media(mimeType, imageResource))
				.call()
				.chatResponse();

			return parseResponse(chatResponse.getResult().getOutput().getText());
		} catch (Exception e) {
			throw new CustomException(MissionErrorCode.AI_REQUEST_FAILED);
		}
	}

	private void validateInput(String prompt) {
		if (prompt == null || prompt.trim().isEmpty()) {
			throw new CustomException(MissionErrorCode.INVALID_PROMPT);
		}
	}

	private MissionResult parseResponse(String response) {

		if (response == null || response.trim().isEmpty()) {
			return MissionResult.DECLINED;
		}

		String cleanResponse = response.trim();
		
		for (MissionResult result : MissionResult.values()) {
			if (cleanResponse.contains(result.getResult())) {
				return result;
			}
		}
		
		return MissionResult.DECLINED;
	}
}
