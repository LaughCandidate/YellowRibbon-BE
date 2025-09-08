package laughcandidate.yellowribbonbe.image.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ImageType {
	JPEG("image/jpeg"),
	JPG("image/jpg"),
	PNG("image/png"),
	GIF("image/gif"),
	WEBP("image/webp"),
	BMP("image/bmp"),
	SVG("image/svg+xml");

	private final String type;
}