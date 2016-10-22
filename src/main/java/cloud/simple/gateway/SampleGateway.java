package cloud.simple.gateway;

import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

import cloud.simple.gateway.conf.DataSourceProperties;

@SpringBootApplication
@EnableEurekaClient
@EnableZuulProxy
// 必须添加@EnableResourceServer，Zuul才会进行Token Relay。
//This by default secures everything in the authorization server except the oauth endpoints, e.g. /oauth/authorize.
@EnableResourceServer
@EnableAuthorizationServer
//@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 60, redisFlushMode = RedisFlushMode.IMMEDIATE)
@EnableConfigurationProperties(DataSourceProperties.class)
public class SampleGateway {

	public static void main(String[] args) throws Exception {
		SpringApplication.run(SampleGateway.class, args);
	}
	
}
