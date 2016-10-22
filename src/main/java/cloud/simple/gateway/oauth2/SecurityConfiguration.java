package cloud.simple.gateway.oauth2;

import java.util.Arrays;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
// Set higher precedence here to handle the authorization and login endpoints here. Otherwise, the resource server configuration
// will kick in for the /login endpoint and you will get “Full Authentication Required” response
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
// @Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
// @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

//	@Autowired
//	private AuthenticationProviderConfig config;

//	@Override
//	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		// @formatter:off
//		auth.inMemoryAuthentication()
//			.withUser("user").password("password").roles("USER")
//				.and()
//			.withUser("paul").password("emu").roles("USER")
//				.and()
//			.withUser("user").password("password").roles("USER")
//			;
//		auth.userDetailsService(config.customUserDetailsService()).passwordEncoder(new BCryptPasswordEncoder());
		// @formatter:on
//	}

	// @Override
	// public void configure(WebSecurity web) throws Exception {
	// web.ignoring().antMatchers("/images/**", "/info");
	// }

	// @Autowired
	// AuthenticationManager authManager;

	private UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter() {
		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		// filter.setAuthenticationManager(authManager);
		AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler("/login?login_error=true");
		filter.setAuthenticationFailureHandler(failureHandler);
		return filter;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		// requestMatchers以外的uri访问权限就由ResourceServerConfigurerAdapter来确定了，这边一定要加入"/oauth/authorize"，否则认证时不会弹出登录form框，只会弹出浏览器对话框
		http.requestMatchers().antMatchers("/login","/logout","/oauth/authorize");
        http.formLogin(); // 显示登录的form表单
        http.logout().logoutUrl("/logout");
//        http.addFilter(usernamePasswordAuthenticationFilter());
        // WebSecurityConfigurerAdapter的优先级高于ResourceServerConfigurerAdapter，如果不设置允许访问登录界面的话，可能会被ResourceServerConfigurerAdapter拦截
        // 由于我这边的ResourceServerConfigurerAdapter只保护了部分url，所以这边可以不用permit login的url
//        http.authorizeRequests().antMatchers("/login").permitAll();
        http.csrf().disable();
			
//        http
//        	.requestMatchers()
//        		.antMatchers("/**")
//        	.requestMatchers().antMatchers("/user")
//        		.and()
//            .authorizeRequests()
//                .antMatchers("/login.html").permitAll()
//                .anyRequest().authenticated()
//                .antMatchers("/**").permitAll()
//                .and()
//            .exceptionHandling()
//                .accessDeniedPage("/login.html?authorization_error=true")
//                .and()
//            .csrf()
//                .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize"))
//                .disable()
//            .logout()
//            	.logoutUrl("/logout")
//                .logoutSuccessUrl("/login.html")
//                .and()
//            .formLogin()
//            	.loginProcessingUrl("/proc/login")   // 处理登录请求的uri
//                .failureUrl("/login.html?authentication_error=true")   // 登录失败时的uri
//                .loginPage("/login.html")   // oauth2显示的登录界面
               ;
        // @formatter:on
	}

}
