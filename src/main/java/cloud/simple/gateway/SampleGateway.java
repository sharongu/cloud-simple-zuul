package cloud.simple.gateway;

import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

@SpringBootApplication
@EnableEurekaClient
//@EnableZuulProxy
// 必须添加@EnableResourceServer，Zuul才会进行Token Relay。
@EnableResourceServer
@EnableAuthorizationServer
//@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 60, redisFlushMode = RedisFlushMode.IMMEDIATE)
public class SampleGateway {

	public static void main(String[] args) throws Exception {
		SpringApplication.run(SampleGateway.class, args);
	}
	
}
