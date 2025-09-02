package laughcandidate.yellowribbonbe.mission.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Table(name = "MISSION")
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Mission {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "mission_id")
	private Long id;

	@Column(name = "category")
	private String category;

	@Column(name = "description")
	private String description;
}
