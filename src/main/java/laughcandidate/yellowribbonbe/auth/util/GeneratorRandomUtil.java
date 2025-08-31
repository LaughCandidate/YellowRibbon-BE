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

	public static String generateRandomUid() {
		String characters = "abcdefghijklmnopqrstuvwxyz0123456789";
		StringBuilder uid = new StringBuilder();
		
		for (int i = 0; i < 6; i++) {
			int index = RANDOM.nextInt(characters.length());
			uid.append(characters.charAt(index));
		}
		
		return uid.toString();
	}
}