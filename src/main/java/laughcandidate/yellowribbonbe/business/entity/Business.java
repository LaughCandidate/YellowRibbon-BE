package laughcandidate.yellowribbonbe.business.entity;

import java.time.LocalDate;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import laughcandidate.yellowribbonbe.global.entity.BaseEntity;
import laughcandidate.yellowribbonbe.user.entity.User;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Table(name = "BUSINESS")
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Business extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "business_id")
	private Long id;

	@Column(name = "business_no", unique = true)
	private String businessNo;

	@Column(name = "owner_name")
	private String ownerName;

	@Column(name = "start_date")
	private LocalDate startDate;

	@Column(name = "business_name")
	private String businessName;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "user_id", nullable = false)
	private User user;

	@Builder
	public Business(String businessName, String businessNo, String ownerName, LocalDate startDate, User user) {
		this.businessName = businessName;
		this.businessNo = businessNo;
		this.ownerName = ownerName;
		this.startDate = startDate;
		this.user = user;
	}
}
