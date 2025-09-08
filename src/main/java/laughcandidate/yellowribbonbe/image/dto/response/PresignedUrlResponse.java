package laughcandidate.yellowribbonbe.image.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

public record PresignedUrlResponse(
	@Schema(description = "Presigned URL", example = "https://bucket.s3.amazonaws.com/uuid?signature=...")
	String presignedUrl,
	
	@Schema(description = "UUID", example = "550e8400-e29b-41d4-a716-446655440000")
	String uuid
) {}