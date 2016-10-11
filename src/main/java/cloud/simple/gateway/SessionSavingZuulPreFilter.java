package cloud.simple.gateway;

import java.util.Enumeration;

import javax.servlet.http.Cookie;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

// 加这个Componet可以给Zuul加一个过滤器，用来查看转发请求时header的内容等，也可以用来往header中加入一些属性，默认情况下不需要，原本是为了转发时加入sessionid，
// 后来发现在application.yml里面只要设置zuul.sensitiveHeaders将Cookie去除掉就可以了，否则Cookie信息不会转发给下游服务
//@Component
public class SessionSavingZuulPreFilter extends ZuulFilter {

	@Override
	public Object run() {
		RequestContext context = RequestContext.getCurrentContext();
		// HttpSession httpSession = context.getRequest().getSession(false);
		// if (httpSession != null)
		// context.addZuulRequestHeader("Cookie", "SESSION=" + httpSession.getId());
		System.out.println("Cookies:");
		Cookie[] cookies = context.getRequest().getCookies();
		if (cookies != null)
			for (Cookie cookie : cookies)
				System.out.println(cookie.getName() + "=" + cookie.getValue());
		System.out.println("Headers:");
		Enumeration<String> names = context.getRequest().getHeaderNames();
		while (names.hasMoreElements()) {
			String name = names.nextElement();
			String value = "";
			Enumeration<String> values = context.getRequest().getHeaders(name);
			while (values.hasMoreElements())
				value += values.nextElement() + ",";
			System.out.println(name + "=" + value);
		}
		return null;
	}

	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public int filterOrder() {
		return 1;
	}

	@Override
	public String filterType() {
		return "pre";
	}

}
