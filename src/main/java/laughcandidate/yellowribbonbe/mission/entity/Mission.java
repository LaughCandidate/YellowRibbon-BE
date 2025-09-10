package laughcandidate.yellowribbonbe.mission.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import laughcandidate.yellowribbonbe.badge.entity.Badge;
import laughcandidate.yellowribbonbe.global.entity.BaseEntity;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Table(name = "MISSION")
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Mission extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "mission_id")
	private Long id;

	@Column(name = "season")
	private Integer season;

	@Column(name = "description")
	private String description;

	@Column(name = "success_description")
	private String successDescription;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "badge_id", nullable = false)
	private Badge badge;
}
