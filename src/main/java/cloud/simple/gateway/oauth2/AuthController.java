package cloud.simple.gateway.oauth2;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.Approval.ApprovalStatus;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.ModelAndView;

@RestController
// @SessionAttributes("authorizationRequest")
public class AuthController {

	// @Autowired
	private ClientDetailsService clientDetailsService;

	// @Autowired
	private ApprovalStore approvalStore;
	
	@Autowired
	private UserDetailsService userDetailsService;

	// @RequestMapping(value = "/oauth/confirm_access", method = RequestMethod.GET)
	public ModelAndView getAccessConfirmation(Map<String, Object> model, Principal principal) throws Exception {
		AuthorizationRequest clientAuth = (AuthorizationRequest) ((ServletRequestAttributes) RequestContextHolder
				.getRequestAttributes()).getRequest().getSession(false).getAttribute("authorizationRequest");
		// AuthorizationRequest clientAuth = (AuthorizationRequest) model.remove("authorizationRequest");
		ClientDetails client = clientDetailsService.loadClientByClientId(clientAuth.getClientId());
		model.put("auth_request", clientAuth);
		model.put("client", client);
		Map<String, String> scopes = new LinkedHashMap<String, String>();
		for (String scope : clientAuth.getScope()) {
			scopes.put(OAuth2Utils.SCOPE_PREFIX + scope, "false");
		}
		for (Approval approval : approvalStore.getApprovals(principal.getName(), client.getClientId())) {
			if (clientAuth.getScope().contains(approval.getScope())) {
				scopes.put(OAuth2Utils.SCOPE_PREFIX + approval.getScope(),
						approval.getStatus() == ApprovalStatus.APPROVED ? "true" : "false");
			}
		}
		model.put("scopes", scopes);
		ModelAndView mv = new ModelAndView("/authorize.html");
		return mv;
	}

	@RequestMapping("/oauth/error")
	public String handleError() throws Exception {
		return "There was a problem with the OAuth2 protocol";
	}

	@RequestMapping("/user")
	public UserDetails user(Principal principal) throws Exception {
//		CustomUserDetail u = new CustomUserDetail();
//		u.setId(principal.getName());
//		u.setUsername(principal.getName());
//		return u;
		CustomUserDetail user = (CustomUserDetail) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		return userDetailsService.loadUserByUsername(principal.getName());
	}

}
