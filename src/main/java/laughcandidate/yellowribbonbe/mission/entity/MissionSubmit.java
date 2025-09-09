package laughcandidate.yellowribbonbe.mission.entity;

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
import laughcandidate.yellowribbonbe.global.entity.Status;
import laughcandidate.yellowribbonbe.image.entity.Image;
import laughcandidate.yellowribbonbe.business.entity.Business;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Table(name = "MISSION_SUBMIT")
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MissionSubmit extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "mission_submit_id")
	private Long id;

	@Enumerated(EnumType.STRING)
	@Column(name = "status")
	private Status status;

	@Column(name = "reason")
	private String reason;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "mission_id", nullable = false)
	private Mission mission;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "business_id", nullable = false)
	private Business business;

	@Builder
	public MissionSubmit(Business business, Mission mission, String reason, Status status) {
		this.business = business;
		this.mission = mission;
		this.reason = reason;
		this.status = status;
	}
	
	public void updateStatus(Status status) {
		this.status = status;
	}
	
	public void updateReason(String reason) {
		this.reason = reason;
	}
}
