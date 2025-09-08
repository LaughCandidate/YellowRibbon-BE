package laughcandidate.yellowribbonbe.image.service;

import java.time.Duration;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import laughcandidate.yellowribbonbe.image.dto.response.PresignedUrlResponse;
import lombok.RequiredArgsConstructor;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;

@Service
@RequiredArgsConstructor
public class ImageService {

	private final S3Presigner s3Presigner;
	
	@Value("${cloud.aws.s3.bucket}")
	private String bucketName;

	public String createPresignedGetUrl(String keyName) {
		GetObjectRequest objectRequest = GetObjectRequest.builder()
			.bucket(bucketName)
			.key(keyName)
			.build();

		GetObjectPresignRequest presignRequest = GetObjectPresignRequest.builder()
			.signatureDuration(Duration.ofMinutes(30))
			.getObjectRequest(objectRequest)
			.build();

		PresignedGetObjectRequest presignedRequest = s3Presigner.presignGetObject(presignRequest);

		return presignedRequest.url().toExternalForm();
	}

	public PresignedUrlResponse createPresignedPutUrl() {
		String keyName = UUID.randomUUID().toString();
		
		PutObjectRequest objectRequest = PutObjectRequest.builder()
			.bucket(bucketName)
			.key(keyName)
			.build();

		PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
			.signatureDuration(Duration.ofMinutes(30))
			.putObjectRequest(objectRequest)
			.build();

		PresignedPutObjectRequest presignedRequest = s3Presigner.presignPutObject(presignRequest);

		return new PresignedUrlResponse(presignedRequest.url().toExternalForm(), keyName);
	}
}
