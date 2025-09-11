package laughcandidate.yellowribbonbe.codef.config;

import io.codef.api.EasyCodef;
import io.codef.api.EasyCodefServiceType;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
@Getter
public class CodefConfig {

    @Value("${codef.demo.client-id}")
    private String demoClientId;

    @Value("${codef.demo.client-secret}")
    private String demoClientSecret;

    @Value("${codef.prod.client-id}")
    private String prodClientId;

    @Value("${codef.prod.client-secret}")
    private String prodClientSecret;

    @Value("${codef.public-key}")
    private String publicKey;

    @Bean
    public EasyCodef easyCodef() {
        EasyCodef codef = new EasyCodef();
        
        try {
            // 데모 환경 설정
            codef.setClientInfoForDemo(demoClientId, demoClientSecret);
            
            // 운영 환경 설정
            codef.setClientInfo(prodClientId, prodClientSecret);
            
            // RSA 암호화를 위한 공개키 설정
            codef.setPublicKey(publicKey);
            
            log.info("Codef client initialized successfully");
            
        } catch (Exception e) {
            log.error("Failed to initialize Codef client", e);
            throw new RuntimeException("Codef client initialization failed", e);
        }
        
        return codef;
    }

    public EasyCodefServiceType getServiceType(boolean isProduction) {
        return isProduction ? EasyCodefServiceType.API : EasyCodefServiceType.SANDBOX;
    }
}
