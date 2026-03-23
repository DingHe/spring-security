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
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import com.nimbusds.jwt.JWTParser;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.converter.Converter;
import org.springframework.core.log.LogMessage;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.util.Assert;

/**
 * An implementation of {@link AuthenticationManagerResolver} that resolves a JWT-based
 * {@link AuthenticationManager} based on the <a href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> in
 * a signed JWT (JWS).
 *
 * To use, this class must be able to determine whether the `iss` claim is trusted. Recall
 * that anyone can stand up an authorization server and issue valid tokens to a resource
 * server. The simplest way to achieve this is to supply a set of trusted issuers in the
 * constructor.
 *
 * This class derives the Issuer from the `iss` claim found in the
 * {@link HttpServletRequest}'s
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>.
 *
 * @author Josh Cummings
 * @since 5.3
 */
// 在典型的 OAuth2 场景中，资源服务器通常只信任一个授权服务器（Issuer）。但在企业级应用或 SaaS 服务中，你可能需要同时信任多个授权服务器（例如：Google、GitHub 以及公司内部的 Keycloak）。
// 该类的核心逻辑是：
// 从传入的 JWT 令牌中解析出 iss（Issuer，发行者）声明。
// 根据这个 iss 的值，动态地决定或创建一个专门为该发行者服务的 AuthenticationManager。
// 使用该管理器完成后续的令牌校验（下载该发行者的公钥、验证签名等）。
public final class JwtIssuerAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {

	private final AuthenticationManager authenticationManager;

	/**
	 * Construct a {@link JwtIssuerAuthenticationManagerResolver} using the provided
	 * parameters
	 * @param trustedIssuers an array of trusted issuers
	 * @deprecated use {@link #fromTrustedIssuers(String...)}
	 */
	// 接收一组信任的 Issuer 字符串。
	@Deprecated(since = "6.2", forRemoval = true)
	public JwtIssuerAuthenticationManagerResolver(String... trustedIssuers) {
		this(Set.of(trustedIssuers));
	}

	/**
	 * Construct a {@link JwtIssuerAuthenticationManagerResolver} using the provided
	 * parameters
	 * @param trustedIssuers a collection of trusted issuers
	 * @deprecated use {@link #fromTrustedIssuers(Collection)}
	 */
	@Deprecated(since = "6.2", forRemoval = true)
	public JwtIssuerAuthenticationManagerResolver(Collection<String> trustedIssuers) {
		Assert.notEmpty(trustedIssuers, "trustedIssuers cannot be empty");
		this.authenticationManager = new ResolvingAuthenticationManager(
				new TrustedIssuerJwtAuthenticationManagerResolver(Set.copyOf(trustedIssuers)::contains));
	}

	/**
	 * Construct a {@link JwtIssuerAuthenticationManagerResolver} using the provided
	 * parameters
	 * @param trustedIssuers an array of trusted issuers
	 * @since 6.2
	 */
	// 接收一组信任的 Issuer 字符串。
	public static JwtIssuerAuthenticationManagerResolver fromTrustedIssuers(String... trustedIssuers) {
		return fromTrustedIssuers(Set.of(trustedIssuers));
	}

	/**
	 * Construct a {@link JwtIssuerAuthenticationManagerResolver} using the provided
	 * parameters
	 * @param trustedIssuers a collection of trusted issuers
	 * @since 6.2
	 */
	public static JwtIssuerAuthenticationManagerResolver fromTrustedIssuers(Collection<String> trustedIssuers) {
		Assert.notEmpty(trustedIssuers, "trustedIssuers cannot be empty");
		return fromTrustedIssuers(Set.copyOf(trustedIssuers)::contains);
	}

	/**
	 * Construct a {@link JwtIssuerAuthenticationManagerResolver} using the provided
	 * parameters
	 * @param trustedIssuers a predicate to validate issuers
	 * @since 6.2
	 */
	public static JwtIssuerAuthenticationManagerResolver fromTrustedIssuers(Predicate<String> trustedIssuers) {
		Assert.notNull(trustedIssuers, "trustedIssuers cannot be null");
		return new JwtIssuerAuthenticationManagerResolver(
				new TrustedIssuerJwtAuthenticationManagerResolver(trustedIssuers));
	}

	/**
	 * Construct a {@link JwtIssuerAuthenticationManagerResolver} using the provided
	 * parameters
	 *
	 * Note that the {@link AuthenticationManagerResolver} provided in this constructor
	 * will need to verify that the issuer is trusted. This should be done via an allowed
	 * set of issuers.
	 *
	 * One way to achieve this is with a {@link Map} where the keys are the known issuers:
	 * <pre>
	 *     Map&lt;String, AuthenticationManager&gt; authenticationManagers = new HashMap&lt;&gt;();
	 *     authenticationManagers.put("https://issuerOne.example.org", managerOne);
	 *     authenticationManagers.put("https://issuerTwo.example.org", managerTwo);
	 *     JwtAuthenticationManagerResolver resolver = new JwtAuthenticationManagerResolver
	 *     	(authenticationManagers::get);
	 * </pre>
	 *
	 * The keys in the {@link Map} are the allowed issuers.
	 * @param issuerAuthenticationManagerResolver a strategy for resolving the
	 * {@link AuthenticationManager} by the issuer
	 */
	public JwtIssuerAuthenticationManagerResolver(
			AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver) {
		Assert.notNull(issuerAuthenticationManagerResolver, "issuerAuthenticationManagerResolver cannot be null");
		this.authenticationManager = new ResolvingAuthenticationManager(issuerAuthenticationManagerResolver);
	}

	/**
	 * Return an {@link AuthenticationManager} based off of the `iss` claim found in the
	 * request's bearer token
	 * @throws OAuth2AuthenticationException if the bearer token is malformed or an
	 * {@link AuthenticationManager} can't be derived from the issuer
	 */
	@Override
	public AuthenticationManager resolve(HttpServletRequest request) {
		return this.authenticationManager;
	}
	// 根据令牌里的 iss 声明，实时寻找对应的认证管理器（AuthenticationManager）来执行验证。
	private static class ResolvingAuthenticationManager implements AuthenticationManager {
		// 它负责在不校验签名的情况下，预先解析 JWT 的 Payload，把 iss（签发者 URL）提取出来。
		private final Converter<BearerTokenAuthenticationToken, String> issuerConverter = new JwtClaimIssuerConverter();
		// 它维护了 Issuer URL 与具体 AuthenticationManager 之间的映射关系。它决定了“如果签发者是 A，就用 A 组装好的解码器”。
		private final AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver;

		ResolvingAuthenticationManager(AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver) {
			this.issuerAuthenticationManagerResolver = issuerAuthenticationManagerResolver;
		}

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			Assert.isTrue(authentication instanceof BearerTokenAuthenticationToken,
					"Authentication must be of type BearerTokenAuthenticationToken");
			BearerTokenAuthenticationToken token = (BearerTokenAuthenticationToken) authentication;
			String issuer = this.issuerConverter.convert(token);
			AuthenticationManager authenticationManager = this.issuerAuthenticationManagerResolver.resolve(issuer);
			if (authenticationManager == null) {
				AuthenticationException ex = new InvalidBearerTokenException("Invalid issuer");
				ex.setAuthenticationRequest(authentication);
				throw ex;
			}
			try {
				// 委托执行真正的认证
				return authenticationManager.authenticate(authentication);
			}
			catch (AuthenticationException ex) {
				ex.setAuthenticationRequest(authentication);
				throw ex;
			}
		}

	}

	private static class JwtClaimIssuerConverter implements Converter<BearerTokenAuthenticationToken, String> {

		@Override
		public String convert(@NonNull BearerTokenAuthenticationToken authentication) {
			String token = authentication.getToken();
			try {
				String issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();
				if (issuer != null) {
					return issuer;
				}
			}
			catch (Exception cause) {
				AuthenticationException ex = new InvalidBearerTokenException(cause.getMessage(), cause);
				ex.setAuthenticationRequest(authentication);
				throw ex;
			}
			AuthenticationException ex = new InvalidBearerTokenException("Missing issuer");
			ex.setAuthenticationRequest(authentication);
			throw ex;
		}

	}
	// 主要职责是：针对受信任的发行者（Issuer），动态创建并缓存对应的 AuthenticationManager。
	// 这个类的作用可以形象地比喻为一个“认证中心仓库”：
	// 当一个请求带着某个 Issuer 进来时，它先检查这个 Issuer 是否在“白名单”（受信任）中。
	// 如果在白名单中，它会检查仓库里是否已经造好了针对这个 Issuer 的“校验器”。
	// 如果没造好，它会实时去该 Issuer 的服务器下载公钥配置（OIDC Discovery）并造一个，然后存进仓库（缓存）以备下次使用。
	static class TrustedIssuerJwtAuthenticationManagerResolver implements AuthenticationManagerResolver<String> {

		private final Log logger = LogFactory.getLog(getClass());
		// 核心缓存。
		// 使用 ConcurrentHashMap 确保多线程安全。Key 是 Issuer 的 URL，Value 是已经构建好的认证管理器。
		private final Map<String, AuthenticationManager> authenticationManagers = new ConcurrentHashMap<>();
		// 信任断言。一个函数式接口，用于判断传入的 Issuer 字符串是否合法。
		// 例如：iss -> iss.startsWith("https://auth.example.com")。
		private final Predicate<String> trustedIssuer;

		TrustedIssuerJwtAuthenticationManagerResolver(Predicate<String> trustedIssuer) {
			this.trustedIssuer = trustedIssuer;
		}
		// 核心方法
		@Override
		public AuthenticationManager resolve(String issuer) {
			// 如果返回 false，则直接进入 else 分支记录日志并返回 null。这意味着该令牌即使签名正确，但因为来源不可信，系统也会拒绝处理。
			if (this.trustedIssuer.test(issuer)) {
				// 如果缓存里有，直接拿；如果没有，执行 Lambda 表达式里的逻辑。
				AuthenticationManager authenticationManager = this.authenticationManagers.computeIfAbsent(issuer,
						(k) -> {
							this.logger.debug("Constructing AuthenticationManager");
							// 这行代码会发起网络请求（访问 issuer/.well-known/openid-configuration）。
							// 它会自动获取该发行者的 JWK Set URI（公钥路径），并构建一个能够校验签名和有效期的 JwtDecoder。
							JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(issuer);
							// 构建一个标准的 JWT 认证提供者，并将其 authenticate 方法封装为 AuthenticationManager 返回。
							return new JwtAuthenticationProvider(jwtDecoder)::authenticate;
						});
				this.logger.debug(LogMessage.format("Resolved AuthenticationManager for issuer '%s'", issuer));
				return authenticationManager;
			}
			else {
				this.logger.debug("Did not resolve AuthenticationManager since issuer is not trusted");
			}
			return null;
		}

	}

}
