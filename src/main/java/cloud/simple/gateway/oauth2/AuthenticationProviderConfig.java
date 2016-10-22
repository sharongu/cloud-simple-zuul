package cloud.simple.gateway.oauth2;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.builders.JdbcClientDetailsServiceBuilder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import cloud.simple.gateway.conf.DataSourceProperties;

@Configuration
public class AuthenticationProviderConfig {

	@Autowired
	private DataSourceProperties dsProp;

	@Bean
	public DriverManagerDataSource dataSource() {
		DriverManagerDataSource driverManagerDataSource = new DriverManagerDataSource();
		driverManagerDataSource.setDriverClassName(dsProp.getDriverClassName());
		driverManagerDataSource.setUrl(dsProp.getUrl());
		driverManagerDataSource.setUsername(dsProp.getUsername());
		driverManagerDataSource.setPassword(dsProp.getPassword());
		return driverManagerDataSource;
	}

	@Bean
	public JdbcTokenStore tokenStore() {
		return new JdbcTokenStore(dataSource());
	}

	@Bean
	protected AuthorizationCodeServices authorizationCodeServices() {
		return new JdbcAuthorizationCodeServices(dataSource());
	}

	@Bean
	public CustomUserDetailsService customUserDetailsService() {
		CustomUserDetailsService service = new CustomUserDetailsService();
		service.setDataSource(dataSource());
		return service;
	}

	@Bean
	public JdbcClientDetailsService jdbcClientDetailsService() {
		JdbcClientDetailsService service = new JdbcClientDetailsService(dataSource());
		service.setPasswordEncoder(new BCryptPasswordEncoder());
		return service;
	}
	
	@Autowired
	public void init(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(customUserDetailsService()).passwordEncoder(new BCryptPasswordEncoder());
	}

}
