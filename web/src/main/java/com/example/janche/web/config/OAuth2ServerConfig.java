package com.example.janche.web.config;


import com.example.janche.security.service.SecurityUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import javax.sql.DataSource;
import java.util.concurrent.TimeUnit;

/**
 * @author lirong
 * Date 2019-3-18 09:04:36
 */
@Configuration
public class OAuth2ServerConfig {

    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

        @Autowired
        AuthenticationManager authenticationManager;
        @Autowired
        private DataSource dataSource;
        @Autowired
        SecurityUserService userDetailsService;
        @Autowired
        ClientDetailsService clientDetailsService;
        @Autowired
        private AuthorizationCodeServices authorizationCodeServices;

        @Bean
        public TokenStore tokenStore() {
            return new JdbcTokenStore(dataSource);
        }

        @Bean
        public TokenStore jwtTokenStore() {
            return new JwtTokenStore(jwtAccessTokenConverter());
        }

        @Bean
        public JwtAccessTokenConverter jwtAccessTokenConverter(){
            JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
            converter.setSigningKey("testKey");
            return converter;
        }

        /**
         * 密码加密
         */
        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        /**
         * ClientDetails实现
         *
         * @return
         */
        @Bean
        public ClientDetailsService clientDetails() {
            return new JdbcClientDetailsService(dataSource);
        }

        /**
         * 加入对授权码模式的支持
         * @param dataSource
         * @return
         */
        @Bean
        public AuthorizationCodeServices authorizationCodeServices(DataSource dataSource) {
            return new JdbcAuthorizationCodeServices(dataSource);
        }


        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            // 1. 数据库的方式
            clients.withClientDetails(clientDetails());

            // 2. 内存的方式
            // 定义了两个客户端应用的通行证
            // clients.inMemory()
            //         .withClient("sheep1")
            //         .secret(new BCryptPasswordEncoder().encode("123456"))
            //         .authorizedGrantTypes("authorization_code", "refresh_token")
            //         .redirectUris("http://localhost:8086/login")
            //         .scopes("all")
            //         .autoApprove(false)
            //         .and()
            //         .withClient("sheep2")
            //         .secret(new BCryptPasswordEncoder().encode("123456"))
            //         .authorizedGrantTypes("authorization_code", "refresh_token")
            //         .redirectUris("http://localhost:8087/login")
            //         .scopes("all")
            //         .autoApprove(false);
        }


        /**
         * 声明授权和token的端点以及token的服务的一些配置信息，
         * 比如采用什么存储方式、token的有效期等
         * @param endpoints
         */
        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) {

            endpoints
                    .tokenStore(jwtTokenStore())
                    .accessTokenConverter(jwtAccessTokenConverter())
                    .authenticationManager(authenticationManager)
                    .userDetailsService(userDetailsService)
                    .authorizationCodeServices(authorizationCodeServices);
                    // .setClientDetailsService(clientDetailsService);

            DefaultTokenServices tokenServices = (DefaultTokenServices) endpoints.getDefaultAuthorizationServerTokenServices();
            tokenServices.setTokenStore(endpoints.getTokenStore());
            tokenServices.setSupportRefreshToken(true);
            tokenServices.setClientDetailsService(endpoints.getClientDetailsService());
            tokenServices.setTokenEnhancer(endpoints.getTokenEnhancer());
            tokenServices.setAccessTokenValiditySeconds((int) TimeUnit.SECONDS.toSeconds(60)); // 一分钟有效期
            endpoints.tokenServices(tokenServices);
        }


        /**
         * 声明安全约束，哪些允许访问，哪些不允许访问
         * @param security
         */
        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) {
            //允许表单认证
            security.allowFormAuthenticationForClients();
            security.passwordEncoder(passwordEncoder());
            // 对于CheckEndpoint控制器[框架自带的校验]的/oauth/check端点允许所有客户端发送器请求而不会被Spring-security拦截
            security.tokenKeyAccess("isAuthenticated()");
            // oauthServer.addTokenEndpointAuthenticationFilter(new Oauth2Filter());

        }

    }

}
