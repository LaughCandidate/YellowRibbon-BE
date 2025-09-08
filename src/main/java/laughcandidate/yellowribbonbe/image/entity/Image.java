package laughcandidate.yellowribbonbe.image.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import laughcandidate.yellowribbonbe.global.entity.BaseEntity;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Table(name = "IMAGE")
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Image extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "mission_id")
	private Long id;

	@Column(name = "key", unique = true)
	private String key;

	@Column(name = "original_name")
	private String originalName;

	@Column(name = "size")
	private Integer size;

	@Enumerated(value = EnumType.STRING)
	@Column(name = "type")
	private ImageType type;
}
