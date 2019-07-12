// package com.example.janche.security.token.filter;
//
// import com.example.janche.common.restResult.RestResult;
// import com.example.janche.common.restResult.ResultCode;
// import com.example.janche.web.config.jwt.JwtUtil;
// import lombok.extern.slf4j.Slf4j;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.AuthenticationException;
// import org.springframework.security.core.GrantedAuthority;
// import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
// import org.springframework.stereotype.Component;
//
// import javax.servlet.FilterChain;
// import javax.servlet.ServletException;
// import javax.servlet.http.HttpServletRequest;
// import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;
// import java.util.ArrayList;
// import java.util.HashMap;
// import java.util.List;
// import java.util.Map;
//
// /**
//  * 登录过滤器
//  *
//  * @author daiyp
//  * @date 2018/9/27
//  */
// @Slf4j
// @Component
// public class LoginFilter extends UsernamePasswordAuthenticationFilter {
//
// 	// @Value("${jwt.refresh_token_expirationminutes}")
// 	private long refresh_token_expirationminutes = 5;
//
//     // @Value("${jwt.expirate}")
//     private long token_expirationminutes = 2;
//
//     // @Value("${jwt.secret}")
//     private String secret = "janche";
//
//     @Autowired
//     private JwtUtil jwtUtil;
//
//
//     @Override
//     public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
//         log.debug("进入登录过滤器");
//     	String username = request.getParameter("username");
//     	String password = request.getParameter("password");
//         log.debug("用户:"+username+" 进行登录");
//         // 返回一个验证令牌
//         return getAuthenticationManager()
//                 .authenticate(new UsernamePasswordAuthenticationToken(username, password));
//     }
//
//     @Override
//     protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
//         response.setContentType("application/json;charset=utf-8");
//         response.setStatus(HttpServletResponse.SC_OK);
//
//         Map<String,Object> param = new HashMap<>();
//         List<String> role_list = new ArrayList<>();
//         for(GrantedAuthority auth: authentication.getAuthorities()){
//             role_list.add(auth.getAuthority());
//         }
//         param.put("roles",role_list);
//
//         String jwtToken = jwtUtil.createJWT(authentication, false);
//         // String refresh_token = JwtUtil.sign(authentication.getName(), new HashMap<>(), secret, refresh_token_expirationminutes*60*1000);
//         // String token = JwtUtil.sign(authentication.getName(), param, secret, token_expirationminutes*60*1000);
//
//         Map tokenMap = new HashMap();
//         // tokenMap.put("refresh_token", refresh_token);
//         tokenMap.put("token", jwtToken);
//         RestResult<Map> result= new RestResult<>(200, "登录成功", tokenMap);
//         response.getOutputStream().write(result.toJson().getBytes());
//     }
//
//     @Override
//     protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
//         response.setContentType("application/json;charset=utf-8");
//         response.setStatus(HttpServletResponse.SC_OK);
//         response.getOutputStream().write(new RestResult<>(ResultCode.LOGIN_ERROR).toJson().getBytes());
//     }
// }
