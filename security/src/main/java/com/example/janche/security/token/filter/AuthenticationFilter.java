// package com.example.janche.security.token.filter;
//
// import com.example.janche.common.restResult.RestResult;
// import com.example.janche.common.restResult.ResultCode;
// import com.example.janche.web.config.jwt.JwtConfig;
// import com.example.janche.web.config.jwt.JwtUtil;
// import com.example.janche.user.service.UserService;
// import lombok.extern.slf4j.Slf4j;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.GrantedAuthority;
// import org.springframework.security.core.authority.SimpleGrantedAuthority;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
//
// import javax.servlet.FilterChain;
// import javax.servlet.ServletException;
// import javax.servlet.http.HttpServletRequest;
// import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;
// import java.util.ArrayList;
// import java.util.List;
//
// /**
//  *token过滤
//  * @author daiyp
//  * @date 2018/9/27
//  */
// @Slf4j
// public class AuthenticationFilter extends BasicAuthenticationFilter {
//
//
// 	private String secret = "janche";
//
// 	@Autowired
// 	private JwtUtil jwtUtil;
//
// 	@Autowired
// 	private JwtConfig jwtConfig;
//
// 	@Autowired
//     private UserService userService;
//
// 	public AuthenticationFilter(AuthenticationManager authenticationManager) {
// 		super(authenticationManager);
// 	}
//
// 	@SuppressWarnings("unchecked")
// 	@Override
//     public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
//
// 		String jwtoken = jwtUtil.getJwtFromRequest(request);
//     	log.debug("进入token验证过滤器");
//     	log.debug("token:"+jwtoken);
//         ArrayList<GrantedAuthority> authorities = new ArrayList<>();
//         String sub = "";
//         StringBuffer roles = new StringBuffer();
//         response.setContentType("application/json;charset=utf-8");
//         response.setStatus(HttpServletResponse.SC_OK);
//         try{
//             if(jwtoken!=null){
// 				List<String> roleStr = (List) JwtUtil.getValueFromToken(jwtoken, "roles", secret);
// 				for(String role: roleStr){
//                     authorities.add(new SimpleGrantedAuthority(role));
//                     roles.append(role).append(",");
//                 }
//                 log.debug("token记录权限:"+roles.toString());
// 				String username = jwtUtil.getUsernameFromJWT(jwtoken);
//     	        SecurityContextHolder.getContext()
//     	        	.setAuthentication(new UsernamePasswordAuthenticationToken(username, null, authorities));
// 				filterChain.doFilter(request,response);
//             }else{
//             	String url = request.getRequestURI();
//             	boolean isPermit = false;
//             	if(!isPermit){
//             		//不带token时,抛出用户未登录的异常
//                     log.debug("用户 未登录");
//                     response.getOutputStream().write(new RestResult<>(ResultCode.UNLOGIN).toJson().getBytes());
//                     return;
//             	}
//             }
//         }catch (Exception e) {
//         	log.debug("用户令牌不合法:"+jwtoken);
//         	log.debug("用户令牌不合法 exception:"+e.getMessage());
//         	response.getOutputStream().write(new RestResult<>(ResultCode.TOKEN_ILLEGAL).toJson().getBytes());
//         	return;
//         }
//
//     }
// }
