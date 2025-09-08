package laughcandidate.yellowribbonbe.image.service;

import java.time.Duration;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import laughcandidate.yellowribbonbe.ai.util.OpenAIUtil;
import laughcandidate.yellowribbonbe.business.entity.Business;
import laughcandidate.yellowribbonbe.business.repository.BusinessRepository;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.BusinessErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.ImageErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.MissionErrorCode;
import laughcandidate.yellowribbonbe.image.dto.response.ImageSaveResponse;
import laughcandidate.yellowribbonbe.image.dto.response.PresignedUrlResponse;
import laughcandidate.yellowribbonbe.image.entity.Image;
import laughcandidate.yellowribbonbe.image.entity.ImageType;
import laughcandidate.yellowribbonbe.image.repository.ImageRepository;
import laughcandidate.yellowribbonbe.mission.entity.Mission;
import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;
import laughcandidate.yellowribbonbe.mission.repository.MissionRepository;
import laughcandidate.yellowribbonbe.mission.repository.MissionSubmitRepository;
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
	private final ImageRepository imageRepository;
	private final MissionRepository missionRepository;
	private final MissionSubmitRepository missionSubmitRepository;
	private final BusinessRepository businessRepository;
	private final OpenAIUtil openAIUtil;
	
	@Value("${cloud.aws.s3.bucket}")
	private String bucketName;

	@Transactional(readOnly = true)
	public PresignedUrlResponse createPresignedGetUrl(Long imageId) {

		Image image = imageRepository.findById(imageId)
			.orElseThrow(() -> new CustomException(ImageErrorCode.IMAGE_NOT_FOUND));

		GetObjectRequest objectRequest = GetObjectRequest.builder()
			.bucket(bucketName)
			.key(image.getUuid())
			.build();

		GetObjectPresignRequest presignRequest = GetObjectPresignRequest.builder()
			.signatureDuration(Duration.ofMinutes(30))
			.getObjectRequest(objectRequest)
			.build();

		PresignedGetObjectRequest presignedRequest = s3Presigner.presignGetObject(presignRequest);

		return new PresignedUrlResponse(presignedRequest.url().toExternalForm(), image.getUuid());
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

	@Transactional
	public ImageSaveResponse saveImage(Long missionId, String uuid, String originalName, Integer size, ImageType imageType, Long businessId) {
		Mission mission = missionRepository.findById(missionId)
			.orElseThrow(() -> new CustomException(MissionErrorCode.MISSION_NOT_FOUND));
		
		Business business = businessRepository.findById(businessId)
			.orElseThrow(() -> new CustomException(BusinessErrorCode.BUSINESS_NOT_FOUND));
		
		MissionSubmit missionSubmit = MissionSubmit.builder()
			.mission(mission)
			.business(business)
			.build();
		
		missionSubmitRepository.save(missionSubmit);
		
		Image image = Image.builder()
			.uuid(uuid)
			.originalName(originalName)
			.size(size)
			.type(imageType)
			.missionSubmit(missionSubmit)
			.build();
		
		imageRepository.save(image);

		return new ImageSaveResponse(image.getId());
	}
}
