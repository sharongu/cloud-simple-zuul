package cloud.simple.gateway;

import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

@SpringBootApplication
@EnableEurekaClient
@EnableZuulProxy
public class SampleGateway {

	public static void main(String[] args) throws Exception {
		SpringApplication.run(SampleGateway.class, args);
	}

}
