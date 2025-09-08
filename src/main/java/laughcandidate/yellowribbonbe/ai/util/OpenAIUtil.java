package laughcandidate.yellowribbonbe.ai.util;

import java.net.URI;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Component;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;

import laughcandidate.yellowribbonbe.ai.enums.MissionResult;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.MissionErrorCode;
import laughcandidate.yellowribbonbe.image.entity.ImageType;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class OpenAIUtil {

	private final ChatClient chatClient;

	public MissionResult sendPrompt(String prompt, String imageUrl, ImageType imageType) {
		validateInput(prompt);
		validateImageUrl(imageUrl);

		try {
			Resource imageResource = new UrlResource(URI.create(imageUrl));
			MimeType mimeType = getMimeTypeFromImageType(imageType);

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

	private void validateImageUrl(String imageUrl) {
		if (imageUrl == null || imageUrl.trim().isEmpty()) {
			throw new CustomException(MissionErrorCode.INVALID_IMAGE_FILE);
		}
	}

	private MimeType getMimeTypeFromImageType(ImageType imageType) {
		return switch (imageType) {
			case JPEG, JPG -> MimeTypeUtils.IMAGE_JPEG;
			case PNG -> MimeTypeUtils.IMAGE_PNG;
			case GIF -> MimeTypeUtils.IMAGE_GIF;
			case WEBP -> MimeType.valueOf("image/webp");
			case BMP -> MimeType.valueOf("image/bmp");
			case SVG -> MimeType.valueOf("image/svg+xml");
		};
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
