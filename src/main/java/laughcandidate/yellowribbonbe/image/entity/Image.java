package laughcandidate.yellowribbonbe.image.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import laughcandidate.yellowribbonbe.global.entity.BaseEntity;
import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Table(name = "IMAGE")
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Image extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "image_id")
	private Long id;

	@Column(name = "uuid", unique = true)
	private String uuid;

	@Column(name = "original_name")
	private String originalName;

	@Column(name = "size")
	private Integer size;

	@Enumerated(value = EnumType.STRING)
	@Column(name = "type")
	private ImageType type;

	@Column(name = "is_success")
	private Boolean isSuccess;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "mission_submit_id", nullable = false)
	private MissionSubmit missionSubmit;

	@Builder
	public Image(Boolean isSuccess, MissionSubmit missionSubmit, String originalName, Integer size, ImageType type,
		String uuid) {
		this.isSuccess = isSuccess;
		this.missionSubmit = missionSubmit;
		this.originalName = originalName;
		this.size = size;
		this.type = type;
		this.uuid = uuid;
	}
	
	public void updateIsSuccess(Boolean isSuccess) {
		this.isSuccess = isSuccess;
	}
}
