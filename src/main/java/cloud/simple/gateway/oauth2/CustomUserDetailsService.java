package cloud.simple.gateway.oauth2;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

public class CustomUserDetailsService extends JdbcDaoSupport implements UserDetailsService {

	public static void main(String args[]) throws Exception {
		String cryptedPassword = new BCryptPasswordEncoder().encode("secret");
		System.out.println(cryptedPassword);
	}
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		List<CustomUserDetail> users = getJdbcTemplate().query("select userid,username,password,enabled from users where username=?",
				new String[] { username }, new RowMapper<CustomUserDetail>() {
					public CustomUserDetail mapRow(ResultSet rs, int rowNum) throws SQLException {
						CustomUserDetail ud = new CustomUserDetail();
						ud.setUserId(rs.getLong(1));
						ud.setUsername(rs.getString(2));
						ud.setPassword(rs.getString(3));
						ud.setEnabled(rs.getBoolean(4));
						return ud;
					}
				});
		if (users.size() == 0) {
			this.logger.debug("Query returned no results for user '" + username + "'");
			throw new UsernameNotFoundException(username);
		}
		CustomUserDetail user = users.get(0);
		List<GrantedAuthority> authorities = getJdbcTemplate().query("select authority from user_authorities where userid=?",
				new Long[] { user.getUserId() }, new RowMapper<GrantedAuthority>() {
					public GrantedAuthority mapRow(ResultSet rs, int rowNum) throws SQLException {
						String authority = rs.getString(1);
						return new SimpleGrantedAuthority(authority);
					}
				});
		user.setAuthorities(authorities);
		return user;
	}

}
