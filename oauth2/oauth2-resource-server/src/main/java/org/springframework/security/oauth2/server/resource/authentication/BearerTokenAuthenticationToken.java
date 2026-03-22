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

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} that contains a
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>.
 *
 * Used by {@link BearerTokenAuthenticationFilter} to prepare an authentication attempt
 * and supported by {@link JwtAuthenticationProvider}.
 *
 * @author Josh Cummings
 * @since 5.1
 */
// BearerTokenAuthenticationToken 是 Spring Security OAuth2 资源服务器（Resource Server）模块中的一个关键类。它专门用于处理符合 RFC 6750 标准的 Bearer Token（通常是 JWT 或不透明令牌）。
// 要用于 OAuth2 资源服务器的认证预处理阶段。
// 非对称性质：它是一个“未认证”的令牌。当客户端在 HTTP Header 中携带 Authorization: Bearer <token> 访问 API 时，
// BearerTokenAuthenticationFilter 会截获这个字符串并将其封装进 BearerTokenAuthenticationToken。
// 传递载体：它的唯一目的是将原始的加密字符串（Token）传递给后端的认证处理器（如 JwtAuthenticationProvider 或 OpaqueTokenAuthenticationProvider）。
// 认证前后的转换：
// 认证前：它是 BearerTokenAuthenticationToken（只包含一个字符串）。
// 认证后：它会被转换成 JwtAuthenticationToken 或 BearerTokenAuthentication（包含解析后的 Claims 和真正的权限）。
public class BearerTokenAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	// 核心数据。存储从请求中提取的原始 Bearer Token 字符串（例如那串长长的 JWT 字符）。
	// 由于是 private final，一旦创建便不可更改。
	private final String token;

	/**
	 * Create a {@code BearerTokenAuthenticationToken} using the provided parameter(s)
	 * @param token - the bearer token
	 */
	public BearerTokenAuthenticationToken(String token) {
		super(Collections.emptyList());
		Assert.hasText(token, "token cannot be empty");
		this.token = token;
	}

	/**
	 * Get the
	 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
	 * Token</a>
	 * @return the token that proves the caller's authority to perform the
	 * {@link jakarta.servlet.http.HttpServletRequest}
	 */
	public String getToken() {
		return this.token;
	}

	@Override
	public Object getCredentials() {
		return this.getToken();
	}

	@Override
	public Object getPrincipal() {
		return this.getToken();
	}

}
