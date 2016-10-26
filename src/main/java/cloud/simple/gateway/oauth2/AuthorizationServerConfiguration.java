package cloud.simple.gateway.oauth2;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import cloud.simple.gateway.conf.DataSourceProperties;

@Configuration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private AuthenticationProviderConfig config;

	// @Autowired
	// private UserApprovalHandler userApprovalHandler;

	@Autowired
	// @Qualifier("authenticationManagerBean")
	private AuthenticationManager auth;

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

		// @formatter:off
		clients
//			.inMemory().withClient("pipa")
////		 			.resourceIds(SPARKLR_RESOURCE_ID)
//		 			.authorizedGrantTypes("authorization_code", "implicit", "client_credentials","password")
//		 			.authorities("ROLE_CLIENT")
//		 			.scopes("read", "write")
//		 			.secret("secret")
//		 			.autoApprove(true)
//		 		.and()
//		 		.withClient("tonr2")
////		 			.resourceIds(SPARKLR_RESOURCE_ID)
//		 			.authorizedGrantTypes("authorization_code", "implicit", "client_credentials","password")
//		 			.authorities("ROLE_CLIENT")
//		 			.scopes("read", "write")
//		 			.secret("secret")
////		 			.redirectUris(tonrRedirectUri)
//		 		.and()
//	 		    .withClient("tonr3")
//// 			        .resourceIds(SPARKLR_RESOURCE_ID)
// 			        .authorizedGrantTypes("authorization_code", "implicit", "client_credentials","password")
// 			        .authorities("ROLE_CLIENT")
// 			        .scopes("read", "write")
// 			        .secret("secret")
//// 			        .redirectUris("http://anywhere?key=value")
//	 		    .and()
// 		        .withClient("my-trusted-client")
//			            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
//			            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
//			            .scopes("read", "write", "trust")
//			            .accessTokenValiditySeconds(60)
//	 		    .and()
// 		        .withClient("my-trusted-client-with-secret")
//			            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
//			            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
//			            .scopes("read", "write", "trust")
//			            .secret("somesecret")
// 		        .and()
//		            .withClient("my-less-trusted-client")
//		            .authorizedGrantTypes("authorization_code", "implicit")
//		            .authorities("ROLE_CLIENT")
//		            .scopes("read", "write", "trust")
// 		        .and()
//	            .withClient("my-less-trusted-autoapprove-client")
//	                .authorizedGrantTypes("implicit")
//	                .authorities("ROLE_CLIENT")
//	                .scopes("read", "write", "trust")
//	                .autoApprove(true)
				.withClientDetails(config.clientDetailsService())
				;
		// @formatter:on
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer.passwordEncoder(new BCryptPasswordEncoder())
		// .realm("pipa/client")
				.checkTokenAccess("isAuthenticated()") // 因为/oauth/check_token默认是denyAll.必须手动设置oauthServer.checkTokenAccess("isAuthenticated()");
		// .tokenKeyAccess("isAnonymous()") // 应用于 /oauth/token_key
		// .allowFormAuthenticationForClients()
		;
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		// endpoints.tokenStore(tokenStore).userApprovalHandler(userApprovalHandler)
		endpoints.authenticationManager(auth);
		// 允许以GET，POST方式访问 /oauth/token
		endpoints.allowedTokenEndpointRequestMethods(HttpMethod.POST, HttpMethod.GET);
		endpoints.authorizationCodeServices(config.authorizationCodeServices());
		endpoints.tokenStore(config.tokenStore());
	}

	// 可以进行跨域拦截(CORS)，并且在返回的response header中写入允许跨域访问的信息
	@Bean
	public FilterRegistrationBean corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true);
		config.addAllowedOrigin("*");
		config.addAllowedHeader("*");
		config.addAllowedMethod("OPTIONS");
		config.addAllowedMethod("HEAD");
		config.addAllowedMethod("GET");
		config.addAllowedMethod("PUT");
		config.addAllowedMethod("POST");
		config.addAllowedMethod("DELETE");
		config.addAllowedMethod("PATCH");
		source.registerCorsConfiguration("/**", config);
		final FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
		// 这个必须设为最高优先级，否则被oauth2拦截的请求会没法写入Access-Control-Allow-Origin等header信息
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return bean;
	}

	// @Bean
	// public ApprovalStore approvalStore() throws Exception {
	// TokenApprovalStore store = new TokenApprovalStore();
	// store.setTokenStore(tokenStore);
	// return store;
	// // return new JdbcApprovalStore(dataSource);
	// }

	// @Bean
	// @Lazy
	// @Scope(proxyMode = ScopedProxyMode.TARGET_CLASS)
	// public PipaUserApprovalHandler userApprovalHandler() throws Exception {
	// PipaUserApprovalHandler handler = new PipaUserApprovalHandler();
	// handler.setApprovalStore(approvalStore());
	// handler.setRequestFactory(new DefaultOAuth2RequestFactory(clientDetailsService));
	// handler.setClientDetailsService(clientDetailsService);
	// handler.setUseApprovalStore(true);
	// return handler;
	// }

}
