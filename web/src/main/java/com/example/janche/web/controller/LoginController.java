package com.example.janche.web.controller;

import com.example.janche.common.restResult.RestResult;
import com.example.janche.common.restResult.ResultGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * @author lirong
 * @ClassName: LoginController
 * @Description: TODO
 * @date 2019-07-16 14:12
 */
@RestController
@RequestMapping("/")
@Slf4j
public class LoginController {

    // @GetMapping("/logout")
    public RestResult logout(HttpServletRequest request) {
        // Cookie[] cookies = request.getCookies();
        // log.info(cookies.toString());
        // LoginUserDTO user = SecurityUtils.getCurrentUser();
        // String username = user.getUsername();
        // request.getSession().invalidate();
        log.info(request.getSession().getId());
        SecurityContext context = SecurityContextHolder.getContext();
        log.info("context: "+context);
        new SecurityContextLogoutHandler().logout(request, null, null);


        // redisTemplate.delete(Constant.REDIS_PERM_KEY_PREFIX + username);
        return ResultGenerator.genSuccessResult().setMessage("退出成功");
    }
}
