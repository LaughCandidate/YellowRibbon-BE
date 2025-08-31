package laughcandidate.yellowribbonbe.business.config;

import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableFeignClients(basePackages = "laughcandidate.yellowribbonbe.business.client")
public class FeignConfig {
}