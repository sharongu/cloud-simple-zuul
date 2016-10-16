package cloud.simple.gateway.oauth2;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.authentication.AuthenticationManager;
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

@Configuration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

	private static final String SPARKLR_RESOURCE_ID = "pipa";

//	@Autowired
//	private TokenStore tokenStore;
//
//	@Autowired
//	private ClientDetailsService clientDetailsService;
//
//	@Autowired
//	private UserApprovalHandler userApprovalHandler;

	// @Autowired
	// DataSource dataSource;

	@Autowired
	// @Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

		// @formatter:off
		clients.inMemory().withClient("tonr")
//		 			.resourceIds(SPARKLR_RESOURCE_ID)
		 			.authorizedGrantTypes("authorization_code", "implicit", "client_credentials")
		 			.authorities("ROLE_CLIENT")
		 			.scopes("read", "write")
		 			.secret("secret")
		 			.autoApprove(true)
		 		.and()
		 		.withClient("tonr-with-redirect")
		 			.resourceIds(SPARKLR_RESOURCE_ID)
		 			.authorizedGrantTypes("authorization_code", "implicit")
		 			.authorities("ROLE_CLIENT")
		 			.scopes("read", "write")
		 			.secret("secret")
//		 			.redirectUris(tonrRedirectUri)
		 		.and()
	 		    .withClient("my-client-with-registered-redirect")
 			        .resourceIds(SPARKLR_RESOURCE_ID)
 			        .authorizedGrantTypes("authorization_code", "client_credentials")
 			        .authorities("ROLE_CLIENT")
 			        .scopes("read", "trust")
 			        .redirectUris("http://anywhere?key=value")
	 		    .and()
 		        .withClient("my-trusted-client")
			            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
			            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
			            .scopes("read", "write", "trust")
			            .accessTokenValiditySeconds(60)
	 		    .and()
 		        .withClient("my-trusted-client-with-secret")
			            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
			            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
			            .scopes("read", "write", "trust")
			            .secret("somesecret")
 		        .and()
		            .withClient("my-less-trusted-client")
		            .authorizedGrantTypes("authorization_code", "implicit")
		            .authorities("ROLE_CLIENT")
		            .scopes("read", "write", "trust")
 		        .and()
	            .withClient("my-less-trusted-autoapprove-client")
	                .authorizedGrantTypes("implicit")
	                .authorities("ROLE_CLIENT")
	                .scopes("read", "write", "trust")
	                .autoApprove(true);
		// @formatter:on
		// clients.withClientDetails(clientDetailsService);
	}

//	@Bean
//	public TokenStore tokenStore() {
//		return new InMemoryTokenStore();
//	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer
//			.realm("pipa/client")
			.checkTokenAccess("isAuthenticated()") //因为/oauth/check_token默认是denyAll.必须手动设置oauthServer.checkTokenAccess("isAuthenticated()");
//		 .tokenKeyAccess("isAnonymous()") // 应用于 /oauth/token_key
//				.allowFormAuthenticationForClients();
		 ;
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//		endpoints.tokenStore(tokenStore).userApprovalHandler(userApprovalHandler)
//				.authenticationManager(authenticationManager);
		endpoints.authenticationManager(authenticationManager);
	}

//	@Bean
//	public ApprovalStore approvalStore() throws Exception {
//		TokenApprovalStore store = new TokenApprovalStore();
//		store.setTokenStore(tokenStore);
//		return store;
//		// return new JdbcApprovalStore(dataSource);
//	}

	// @Bean
	// public JdbcClientDetailsService clientDetailsService() {
	// return new JdbcClientDetailsService(dataSource);
	// }

	// @Bean
	// public AuthorizationCodeServices authorizationCodeServices() {
	// return new JdbcAuthorizationCodeServices(dataSource);
	// }

//	@Bean
//	@Lazy
//	@Scope(proxyMode = ScopedProxyMode.TARGET_CLASS)
//	public PipaUserApprovalHandler userApprovalHandler() throws Exception {
//		PipaUserApprovalHandler handler = new PipaUserApprovalHandler();
//		handler.setApprovalStore(approvalStore());
//		handler.setRequestFactory(new DefaultOAuth2RequestFactory(clientDetailsService));
//		handler.setClientDetailsService(clientDetailsService);
//		handler.setUseApprovalStore(true);
//		return handler;
//	}

}
