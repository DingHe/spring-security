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

package org.springframework.security.oauth2.server.resource.web.authentication;

import java.io.IOException;
import java.util.Map;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates requests that contain an OAuth 2.0
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>.
 *
 * This filter should be wired with an {@link AuthenticationManager} that can authenticate
 * a {@link BearerTokenAuthenticationToken}.
 *
 * @author Josh Cummings
 * @author Vedran Pavic
 * @author Joe Grandja
 * @author Jeongjin Kim
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750" target="_blank">The OAuth 2.0
 * Authorization Framework: Bearer Token Usage</a>
 * @see JwtAuthenticationProvider
 */
// BearerTokenAuthenticationFilter 是 Spring Security OAuth2 资源服务器（Resource Server）核心组件。它的主要任务是拦截请求，从中提取 Bearer Token（通常是 JWT 或 Opaque Token），并将其交给认证管理器进行验证。
// BearerTokenAuthenticationFilter 的核心职责可以概括为以下几点：
// 令牌提取：从 HTTP 请求中（默认从 Authorization 请求头）提取 Bearer Token。
// 身份验证请求封装：将提取到的字符串令牌封装成 BearerTokenAuthenticationToken 对象。
// 调用认证管理器：利用 AuthenticationManager 对令牌进行验证（例如校验签名、有效期、权限等）。
// 安全上下文管理：认证成功后，将认证结果存入 SecurityContextHolder，供后续过滤器或业务代码使用。
// 错误处理：如果令牌无效或缺失，负责触发相应的失败处理器或返回 401 Unauthorized 响应。
// 防止降级攻击：检查令牌是否为 DPoP 绑定的令牌，防止安全的 DPoP 令牌被作为普通 Bearer 令牌误用。
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {
	// 核心策略。
	// 用于解析并返回适用于当前请求的 AuthenticationManager。
	// 支持多租户场景（根据请求动态决定使用哪个认证管理器）。
	private final AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;
	// 存储策略。
	// 定义如何存储和获取 SecurityContext，默认为本地线程（ThreadLocal）模式。
	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();
	// 认证入口点。
	// 当认证失败（如 Token 过期、无效）时，由它负责返回符合 RFC 6750 标准的错误响应头。
	private AuthenticationEntryPoint authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();
	// 失败处理器。
	// 默认封装了 authenticationEntryPoint，用于统一处理认证异常。
	private AuthenticationFailureHandler authenticationFailureHandler = new AuthenticationEntryPointFailureHandler(
			(request, response, exception) -> this.authenticationEntryPoint.commence(request, response, exception));
	// 令牌解析器。
	// 定义从请求的哪个位置获取 Token，默认从 Authorization: Bearer <token> 获取。
	private BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
	// 详情源。用于构建 Web 认证详情（如远程 IP 地址、Session ID），并存入 Authentication 对象中。
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
	// 上下文存储库。负责将 SecurityContext 持久化，以便在请求生命周期内或跨请求使用。
	private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

	/**
	 * Construct a {@code BearerTokenAuthenticationFilter} using the provided parameter(s)
	 * @param authenticationManagerResolver
	 */
	// 接收一个解析器。适用于需要根据请求动态选择认证逻辑的复杂场景。
	public BearerTokenAuthenticationFilter(
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
		Assert.notNull(authenticationManagerResolver, "authenticationManagerResolver cannot be null");
		this.authenticationManagerResolver = authenticationManagerResolver;
	}

	/**
	 * Construct a {@code BearerTokenAuthenticationFilter} using the provided parameter(s)
	 * @param authenticationManager
	 */
	// 接收一个固定的认证管理器。
	// 内部会将其包装成一个简单的解析器，始终返回该管理器。
	public BearerTokenAuthenticationFilter(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManagerResolver = (request) -> authenticationManager;
	}

	/**
	 * Extract any
	 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
	 * Token</a> from the request and attempt an authentication.
	 * @param request
	 * @param response
	 * @param filterChain
	 * @throws ServletException
	 * @throws IOException
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String token;
		try {
			// 尝试获取 Token。
			token = this.bearerTokenResolver.resolve(request);
		}
		catch (OAuth2AuthenticationException invalid) {
			this.logger.trace("Sending to authentication entry point since failed to resolve bearer token", invalid);
			this.authenticationEntryPoint.commence(request, response, invalid);
			return;
		}
		if (token == null) {
		// 无 Token 处理：如果 token == null，说明当前请求不带 Bearer Token。此时执行 filterChain.doFilter 让请求继续流向后续过滤器（如匿名身份验证器），然后直接 return。
			this.logger.trace("Did not process request since did not find bearer token");
			filterChain.doFilter(request, response);
			return;
		}
		// 认证请求封装
		BearerTokenAuthenticationToken authenticationRequest = new BearerTokenAuthenticationToken(token);
		authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

		try {
			// 通过解析器获取当前请求对应的 AuthenticationManager。
			AuthenticationManager authenticationManager = this.authenticationManagerResolver.resolve(request);
			// 调用 authenticate 方法。
			// 此时，系统通常会委派给 JwtAuthenticationProvider 或 OpaqueTokenAuthenticationProvider 来验证令牌的签名、有效期和权限。
			Authentication authenticationResult = authenticationManager.authenticate(authenticationRequest);
			// DPoP (Demonstrating Proof-of-Possession) 是一种比普通 Bearer Token 更安全的机制。如果一个令牌在签发时是绑定了客户端私钥（DPoP）的，那么它严禁作为普通 Bearer Token 发送
			if (isDPoPBoundAccessToken(authenticationResult)) {
				// Prevent downgraded usage of DPoP-bound access tokens,
				// by rejecting a DPoP-bound access token received as a bearer token.
				BearerTokenError error = BearerTokenErrors.invalidToken("Invalid bearer token");
				throw new OAuth2AuthenticationException(error);
			}
			// 成功后的上下文持久化 (Success Handling)
			SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
			context.setAuthentication(authenticationResult);
			this.securityContextHolderStrategy.setContext(context);
			this.securityContextRepository.saveContext(context, request, response);
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authenticationResult));
			}
			filterChain.doFilter(request, response);
		}
		catch (AuthenticationException failed) {
			this.securityContextHolderStrategy.clearContext();
			this.logger.trace("Failed to process authentication request", failed);
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, failed);
		}
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	/**
	 * Sets the {@link SecurityContextRepository} to save the {@link SecurityContext} on
	 * authentication success. The default action is not to save the
	 * {@link SecurityContext}.
	 * @param securityContextRepository the {@link SecurityContextRepository} to use.
	 * Cannot be null.
	 */
	public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
	}

	/**
	 * Set the {@link BearerTokenResolver} to use. Defaults to
	 * {@link DefaultBearerTokenResolver}.
	 * @param bearerTokenResolver the {@code BearerTokenResolver} to use
	 */
	public void setBearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
		Assert.notNull(bearerTokenResolver, "bearerTokenResolver cannot be null");
		this.bearerTokenResolver = bearerTokenResolver;
	}

	/**
	 * Set the {@link AuthenticationEntryPoint} to use. Defaults to
	 * {@link BearerTokenAuthenticationEntryPoint}.
	 * @param authenticationEntryPoint the {@code AuthenticationEntryPoint} to use
	 */
	public void setAuthenticationEntryPoint(final AuthenticationEntryPoint authenticationEntryPoint) {
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	/**
	 * Set the {@link AuthenticationFailureHandler} to use. Default implementation invokes
	 * {@link AuthenticationEntryPoint}.
	 * @param authenticationFailureHandler the {@code AuthenticationFailureHandler} to use
	 * @since 5.2
	 */
	public void setAuthenticationFailureHandler(final AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	/**
	 * Set the {@link AuthenticationDetailsSource} to use. Defaults to
	 * {@link WebAuthenticationDetailsSource}.
	 * @param authenticationDetailsSource the {@code AuthenticationConverter} to use
	 * @since 5.5
	 */
	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	private static boolean isDPoPBoundAccessToken(Authentication authentication) {
		if (!(authentication instanceof AbstractOAuth2TokenAuthenticationToken<?> accessTokenAuthentication)) {
			return false;
		}
		ClaimAccessor accessTokenClaims = accessTokenAuthentication::getTokenAttributes;
		String jwkThumbprintClaim = null;
		Map<String, Object> confirmationMethodClaim = accessTokenClaims.getClaimAsMap("cnf");
		if (!CollectionUtils.isEmpty(confirmationMethodClaim) && confirmationMethodClaim.containsKey("jkt")) {
			jwkThumbprintClaim = (String) confirmationMethodClaim.get("jkt");
		}
		return StringUtils.hasText(jwkThumbprintClaim);
	}

}
