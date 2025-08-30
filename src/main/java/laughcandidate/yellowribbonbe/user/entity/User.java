package laughcandidate.yellowribbonbe.user.entity;

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
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Table(name = "USERS")
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "user_id")
	private Long id;

	@Column(name = "password")
	private String password;

	@Column(name = "uid", unique = true)
	private String uid;

	@Column(name = "name")
	private String name;

	@Column(name = "phone", unique = true)
	private String phone;

	@Enumerated(value = EnumType.STRING)
	@Column(name = "role")
	private Role role;

	@Column(name = "is_deleted")
	private boolean isDeleted = false;

	@Builder
	public User(String name, String password, String phone,
		String uid) {
		this.name = name;
		this.password = password;
		this.phone = phone;
		this.uid = uid;
	}
}