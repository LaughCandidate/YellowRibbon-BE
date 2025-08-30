package laughcandidate.yellowribbonbe.auth.service;

import java.util.Properties;

import org.springframework.stereotype.Service;

import laughcandidate.yellowribbonbe.auth.dto.ImapCredentials;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService {

	private final Properties imapConnectionProperties;
	private final ImapCredentials imapCredentials;

	public String getServerEmail() {
		return imapCredentials.userName();
	}
}
