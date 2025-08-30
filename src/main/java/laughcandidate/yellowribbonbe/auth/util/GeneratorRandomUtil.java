package laughcandidate.yellowribbonbe.auth.util;

import java.security.SecureRandom;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class GeneratorRandomUtil {

	private static final SecureRandom RANDOM = new SecureRandom();

	public static String generateRandomNum() {
		int randomNumber = RANDOM.nextInt(1000000);
		return String.format("%06d", randomNumber);
	}
}