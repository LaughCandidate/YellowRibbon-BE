package laughcandidate.yellowribbonbe.user.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import laughcandidate.yellowribbonbe.user.entity.User;
import laughcandidate.yellowribbonbe.user.repository.custom.UserBusinessInfoCustom;

public interface UserRepository extends JpaRepository<User, Long>, UserBusinessInfoCustom {

	boolean existsByPhone(String phone);

	Optional<User> findByUid(String uid);
}
