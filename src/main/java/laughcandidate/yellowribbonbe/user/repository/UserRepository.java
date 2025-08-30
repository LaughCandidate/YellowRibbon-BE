package laughcandidate.yellowribbonbe.user.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import laughcandidate.yellowribbonbe.user.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByPhoneAndIsDeletedFalse(String loginId);
}
