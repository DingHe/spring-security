/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation of the {@link Jwt}-encoded
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>s for protecting OAuth 2.0 Resource Servers.
 * <p>
 * <p>
 * This {@link AuthenticationProvider} is responsible for decoding and verifying a
 * {@link Jwt}-encoded access token, returning its claims set as part of the
 * {@link Authentication} statement.
 * <p>
 * <p>
 * Scopes are translated into {@link GrantedAuthority}s according to the following
 * algorithm:
 *
 * 1. If there is a "scope" or "scp" attribute, then if a {@link String}, then split by
 * spaces and return, or if a {@link Collection}, then simply return 2. Take the resulting
 * {@link Collection} of {@link String}s and prepend the "SCOPE_" keyword, adding as
 * {@link GrantedAuthority}s.
 *
 * @author Josh Cummings
 * @author Joe Grandja
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @since 5.1
 * @see AuthenticationProvider
 * @see JwtDecoder
 */
// JwtAuthenticationProvider 是 Spring Security OAuth2 资源服务器（Resource Server）架构中的核心组件。它充当了验证令牌与生成用户权限之间的桥梁。
// 将一个加密的、不可读的 JWT 字符串，转变为 Spring Security 上下文可以理解的认证对象（Authentication）。
// 具体来说，它完成了以下三件事：
// 解码与验证：调用 JwtDecoder 检查令牌的签名是否正确、是否过期。
// 模型转换：将解码后的 Jwt 对象（包含 Claims 声明）转换为 Spring Security 内部的 AbstractAuthenticationToken。
// 权限映射：默认情况下，它负责将 JWT 中的 scope 或 scp 声明提取出来，并加上 SCOPE_ 前缀，作为用户的 GrantedAuthority（已授予的权限）。
public final class JwtAuthenticationProvider implements AuthenticationProvider {

	private final Log logger = LogFactory.getLog(getClass());
	// 核心解密器。
	// 这是一个 final 属性，在构造时注入。它负责处理复杂的密码学逻辑（如解析 Base64、验证 RSA 签名、检查 exp 过期时间等）。
	private final JwtDecoder jwtDecoder;
	// 策略转换器。它决定了如何从 Jwt 对象中提取信息并填充到认证令牌中。
	// 默认实现会将 scope 映射为权限，但你可以通过 set 方法替换它，以支持自定义的角色映射逻辑（例如从 roles 声明中读取权限）。
	private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = new JwtAuthenticationConverter();

	public JwtAuthenticationProvider(JwtDecoder jwtDecoder) {
		Assert.notNull(jwtDecoder, "jwtDecoder cannot be null");
		this.jwtDecoder = jwtDecoder;
	}

	/**
	 * Decode and validate the
	 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
	 * Token</a>.
	 * @param authentication the authentication request object.
	 * @return A successful authentication
	 * @throws AuthenticationException if authentication failed for some reason
	 */
	// 执行认证的核心入口方法。
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// 强转类型：将传入的 Authentication 强制转换为 BearerTokenAuthenticationToken（这是 Filter 层传过来的原始令牌容器）。
		BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;
		// 调用私有的 getJwt 方法进行解码。
		// 解码的过程就是认证的过程
		Jwt jwt = getJwt(bearer);
		// 将 Jwt 变成 Spring 可用的 AbstractAuthenticationToken。
		AbstractAuthenticationToken token = this.jwtAuthenticationConverter.convert(jwt);
		if (token.getDetails() == null) {
			token.setDetails(bearer.getDetails());
		}
		this.logger.debug("Authenticated token");
		// 返回一个已认证（Authenticated）的令牌对象。
		return token;
	}

	private Jwt getJwt(BearerTokenAuthenticationToken bearer) {
		try {
			return this.jwtDecoder.decode(bearer.getToken());
		}
		catch (BadJwtException failed) {
			this.logger.debug("Failed to authenticate since the JWT was invalid");
			throw new InvalidBearerTokenException(failed.getMessage(), failed);
		}
		catch (JwtException failed) {
			throw new AuthenticationServiceException(failed.getMessage(), failed);
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public void setJwtAuthenticationConverter(
			Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {
		Assert.notNull(jwtAuthenticationConverter, "jwtAuthenticationConverter cannot be null");
		this.jwtAuthenticationConverter = jwtAuthenticationConverter;
	}

}
