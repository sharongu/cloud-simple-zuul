package cloud.simple.gateway.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
//@Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
//@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsService userDetailsService;
	
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		// @formatter:off
//		auth.inMemoryAuthentication()
//			.withUser("user").password("password").roles("USER")
//				.and()
//			.withUser("paul").password("emu").roles("USER")
//				.and()
//			.withUser("user").password("password").roles("USER")
//			;
		auth.userDetailsService(userDetailsService);
		// @formatter:on
	}
	
	@Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/images/**", "/info");
    }
	
//	@Override
//    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
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
//               ;
        // @formatter:on
//    }

}
