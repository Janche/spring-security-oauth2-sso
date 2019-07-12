package com.example.janche.security.token.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * token操作
 * @author  daiyp
 * @date 2018-9-26
 */

@Component("tokenService")
public class TokenService {

	@Value("janche.auth.secret")
	private String secret;

	public void init(String secret){
		this.secret=secret;
	}

	/**
	 *
	 * 功能：生成 jwt token<br/>
	 * @param name	实例名
	 * @param param	需要保存的参数
	 * @return
	 *
	 */
	public String sign(String name,Map<String,Object> param,long expirationminutes){
		// return JwtUtil.sign(name, param, secret, expirationminutes*60*1000);
		return null;
	}
	/**
	 *
	 * 功能：从token中获取数据<br/>
	 * @param jwt token
	 * @param key	需要获取的key
	 * @return
	 *
	 */
	public Object getValueFromToken(String jwt,String key){
		// return JwtUtil.verify(jwt, secret).get(key);
		return null;
	}

}
