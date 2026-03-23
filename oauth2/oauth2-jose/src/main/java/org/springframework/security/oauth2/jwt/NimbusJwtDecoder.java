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

package org.springframework.security.oauth2.jwt;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Function;

import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.cache.Cache;
import org.springframework.cache.support.NoOpCache;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * A low-level Nimbus implementation of {@link JwtDecoder} which takes a raw Nimbus
 * configuration.
 *
 * @author Josh Cummings
 * @author Joe Grandja
 * @author Mykyta Bezverkhyi
 * @author Daeho Kwon
 * @since 5.2
 */
// NimbusJwtDecoder 是 Spring Security OAuth2 中最核心的解码实现类。
// 它通过包装 Nimbus JOSE + JWT 库，将底层的 JWT 解析、签名验证逻辑与 Spring Security 的 Jwt 模型结合起来。
// NimbusJwtDecoder 的主要作用是：
// 解析（Parsing）：将加密或签名的 JWT 字符串拆解为 Header、Payload 和 Signature。
// 验证（Verification）：验证 JWT 的签名（JWS）是否合法，确保令牌未被篡改。
// 转换（Conversion）：将 Payload 中的 Claims（声明）转换为 Java 的 Map 结构，并处理类型转换。
// 校验（Validation）：通过可插拔的验证器检查令牌的有效期（exp）、发行者（iss）等业务逻辑。
public final class NimbusJwtDecoder implements JwtDecoder {

	private final Log logger = LogFactory.getLog(getClass());

	private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";
	// 核心处理器（来自 Nimbus 库）。负责具体的签名验证算法执行和 Claims 提取。
	private final JWTProcessor<SecurityContext> jwtProcessor;
	// 类型转换器。
	// 负责将原始的 JSON Map 转换为 Spring Security 规范化的 Map<String, Object>。
	private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = MappedJwtClaimSetConverter
		.withDefaults(Collections.emptyMap());
	// Spring 级别的验证器。
	// 在签名验证通过后，执行如“令牌是否过期”等逻辑检查。
	private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();

	/**
	 * Configures a {@link NimbusJwtDecoder} with the given parameters
	 * @param jwtProcessor - the {@link JWTProcessor} to use
	 */
	public NimbusJwtDecoder(JWTProcessor<SecurityContext> jwtProcessor) {
		Assert.notNull(jwtProcessor, "jwtProcessor cannot be null");
		this.jwtProcessor = jwtProcessor;
	}

	/**
	 * Use this {@link Jwt} Validator
	 * @param jwtValidator - the Jwt Validator to use
	 */
	public void setJwtValidator(OAuth2TokenValidator<Jwt> jwtValidator) {
		Assert.notNull(jwtValidator, "jwtValidator cannot be null");
		this.jwtValidator = jwtValidator;
	}

	/**
	 * Use the following {@link Converter} for manipulating the JWT's claim set
	 * @param claimSetConverter the {@link Converter} to use
	 */
	public void setClaimSetConverter(Converter<Map<String, Object>, Map<String, Object>> claimSetConverter) {
		Assert.notNull(claimSetConverter, "claimSetConverter cannot be null");
		this.claimSetConverter = claimSetConverter;
	}

	/**
	 * Decode and validate the JWT from its compact claims representation format
	 * @param token the JWT value
	 * @return a validated {@link Jwt}
	 * @throws JwtException when the token is malformed or otherwise invalid
	 */
	@Override
	public Jwt decode(String token) throws JwtException {
		// 目的：检查字符串是否符合 JWT 的三段式格式（Header.Payload.Signature）。
		JWT jwt = parse(token);
		// 背景知识：JWT 规范允许一种 none 算法，即没有签名的明文令牌（PlainJWT）。
		// 安全逻辑：在生产环境中，接受 none 算法是极其危险的（任何人都可以伪造身份）。
		if (jwt instanceof PlainJWT) {
			this.logger.trace("Failed to decode unsigned token");
			throw new BadJwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
		}
		// 签名验证与转换 (Cryptographic Verification)
		// 找钥匙：根据 Header 中的 kid 或配置的 jwkSetUri 获取公钥。
		// 验签名：使用算法（如 RS256）计算签名并比对。
		// 转模型：将 Nimbus 的底层对象转换为 Spring Security 统一的 Jwt 领域模型。
		Jwt createdJwt = createJwt(token, jwt);
		// 验证内容：即使签名是真的，令牌也可能已经失效。
		return validateJwt(createdJwt);
	}
	// 将原始的 Base64 编码字符串初步解析为 Nimbus 库可识别的 JWT 对象。
	// 这个阶段只负责“拆解”结构，并不负责“验证”签名。
	private JWT parse(String token) {
		try {
			return JWTParser.parse(token);
		}
		catch (Exception ex) {
			this.logger.trace("Failed to parse token", ex);
			if (ex instanceof ParseException) {
				throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed token"), ex);
			}
			throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
	}
	// 负责调用底层的密码学引擎进行签名验证，并将结果转换为 Spring Security 的标准 Jwt 对象。
	private Jwt createJwt(String token, JWT parsedJwt) {
		try {
			// Verify the signature
			// jwtProcessor 会根据令牌 Header 中的算法（如 RS256）和密钥 ID（kid），从配置的密钥源（JWK Source）中获取对应的公钥。
			JWTClaimsSet jwtClaimsSet = this.jwtProcessor.process(parsedJwt, null);
			// 提取 Header
			// 将原始 JWT 的 Header 部分（包含算法 alg、类型 typ 等）转换为一个通用的 Map 结构，以便后续存入 Spring 的 Jwt 对象。
			Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
			// 因为它会将 Nimbus 提取出的原始声明（通常是 JSON 基本类型）转换为更符合 Java 规范的类型。
			Map<String, Object> claims = this.claimSetConverter.convert(jwtClaimsSet.getClaims());
			// @formatter:off
			// 构建 Jwt 领域模型
			return Jwt.withTokenValue(token)
					.headers((h) -> h.putAll(headers))
					.claims((c) -> c.putAll(claims))
					.build();
			// @formatter:on
		}
		catch (RemoteKeySourceException ex) {
			this.logger.trace("Failed to retrieve JWK set", ex);
			if (ex.getCause() instanceof ParseException) {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed Jwk set"), ex);
			}
			throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
		catch (JOSEException ex) {
			this.logger.trace("Failed to process JWT", ex);
			throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
		catch (Exception ex) {
			this.logger.trace("Failed to process JWT", ex);
			if (ex.getCause() instanceof ParseException) {
				throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed payload"), ex);
			}
			throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
	}
	// 负责检查令牌的“合法性”（逻辑有效）。即使签名是真的，如果令牌已经过期或者签发者不匹配，该方法也会将其拦截。
	private Jwt validateJwt(Jwt jwt) {
		OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);
		if (result.hasErrors()) {
			Collection<OAuth2Error> errors = result.getErrors();
			String validationErrorString = getJwtValidationExceptionMessage(errors);
			throw new JwtValidationException(validationErrorString, errors);
		}
		return jwt;
	}

	private String getJwtValidationExceptionMessage(Collection<OAuth2Error> errors) {
		for (OAuth2Error oAuth2Error : errors) {
			if (StringUtils.hasLength(oAuth2Error.getDescription())) {
				return String.format(DECODING_ERROR_MESSAGE_TEMPLATE, oAuth2Error.getDescription());
			}
		}
		return "Unable to validate Jwt";
	}

	/**
	 * Use the given <a href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * by making an <a href=
	 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID
	 * Provider Configuration Request</a> and using the values in the <a href=
	 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID
	 * Provider Configuration Response</a> to derive the needed
	 * <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri.
	 * @param issuer the <a href=
	 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>
	 * @return a {@link JwkSetUriJwtDecoderBuilder} that will derive the JWK Set uri when
	 * {@link JwkSetUriJwtDecoderBuilder#build} is called
	 * @since 6.1
	 * @see JwtDecoders
	 */
	public static JwkSetUriJwtDecoderBuilder withIssuerLocation(String issuer) {
		return new JwkSetUriJwtDecoderBuilder((rest) -> {
			Map<String, Object> configuration = JwtDecoderProviderConfigurationUtils
				.getConfigurationForIssuerLocation(issuer, rest);
			JwtDecoderProviderConfigurationUtils.validateIssuer(configuration, issuer);
			return configuration.get("jwks_uri").toString();
		}, JwtDecoderProviderConfigurationUtils::getJWSAlgorithms);
	}

	/**
	 * Use the given <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a>
	 * uri.
	 * @param jwkSetUri the JWK Set uri to use
	 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
	 */
	public static JwkSetUriJwtDecoderBuilder withJwkSetUri(String jwkSetUri) {
		return new JwkSetUriJwtDecoderBuilder(jwkSetUri);
	}

	/**
	 * Use the given public key to validate JWTs
	 * @param key the public key to use
	 * @return a {@link PublicKeyJwtDecoderBuilder} for further configurations
	 */
	public static PublicKeyJwtDecoderBuilder withPublicKey(RSAPublicKey key) {
		return new PublicKeyJwtDecoderBuilder(key);
	}

	/**
	 * Use the given {@code SecretKey} to validate the MAC on a JSON Web Signature (JWS).
	 * @param secretKey the {@code SecretKey} used to validate the MAC
	 * @return a {@link SecretKeyJwtDecoderBuilder} for further configurations
	 */
	public static SecretKeyJwtDecoderBuilder withSecretKey(SecretKey secretKey) {
		return new SecretKeyJwtDecoderBuilder(secretKey);
	}

	/**
	 * A builder for creating {@link NimbusJwtDecoder} instances based on a
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a>
	 * uri.
	 */
	// 专门负责根据 JWK Set URI（远程公钥集合地址）来构建解码器。这是多租户或标准 OAuth2 架构中最常用的构建方式。
	// 该 Builder 的核心任务是配置如何从远程获取公钥并验证签名。它处理了网络请求、密钥缓存、算法过滤以及底层 Nimbus 处理器的定制化。
	public static final class JwkSetUriJwtDecoderBuilder {

		private static final JOSEObjectTypeVerifier<SecurityContext> JWT_TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(
				JOSEObjectType.JWT, null);

		private static final JOSEObjectTypeVerifier<SecurityContext> NO_TYPE_VERIFIER = (header, context) -> {
		};
		// 获取 JWK 地址的函数。
		// 之所以用 Function 是因为地址可能需要通过 RestOperations 动态解析。
		private final Function<RestOperations, String> jwkSetUri;

		private Function<JWKSource<SecurityContext>, Set<JWSAlgorithm>> defaultAlgorithms = (source) -> Set
			.of(JWSAlgorithm.RS256);
		// 校验 JWT Header 中的 typ 字段（默认为 JWT）。
		private JOSEObjectTypeVerifier<SecurityContext> typeVerifier = JWT_TYPE_VERIFIER;
		// 允许使用的签名算法集合（如 RS256, PS256）。如果为空，默认仅支持 RS256。
		private final Set<SignatureAlgorithm> signatureAlgorithms = new HashSet<>();
		// 用于发起 HTTP 请求的工具，默认使用 RestTemplate。
		private RestOperations restOperations = new RestTemplate();
		// JWK Set 的缓存实现，默认不缓存（NoOpCache）。
		private Cache cache = new NoOpCache("default");
		// 允许开发者直接修改底层的 ConfigurableJWTProcessor。
		private Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer;
		// 初始化构建器的最小必要状态。它确保了只要构建器存在，就至少拥有一个有效的公钥集合（JWK Set）地址。
		private JwkSetUriJwtDecoderBuilder(String jwkSetUri) {
			Assert.hasText(jwkSetUri, "jwkSetUri cannot be empty");
			this.jwkSetUri = (rest) -> jwkSetUri;
			this.jwtProcessorCustomizer = (processor) -> {
			};
		}
		// 不再硬编码 JWK 的 URL，而是注入两个逻辑函数（Functions），让 URL 和算法在运行时动态推导出来。
		private JwkSetUriJwtDecoderBuilder(Function<RestOperations, String> jwkSetUri,
				Function<JWKSource<SecurityContext>, Set<JWSAlgorithm>> defaultAlgorithms) {
			Assert.notNull(jwkSetUri, "jwkSetUri function cannot be null");
			Assert.notNull(defaultAlgorithms, "defaultAlgorithms function cannot be null");
			this.jwkSetUri = jwkSetUri;
			this.defaultAlgorithms = defaultAlgorithms;
			this.jwtProcessorCustomizer = (processor) -> {
			};
		}

		/**
		 * Whether to use Nimbus's typ header verification. This is {@code true} by
		 * default, however it may change to {@code false} in a future major release.
		 *
		 * <p>
		 * By turning off this feature, {@link NimbusJwtDecoder} expects applications to
		 * check the {@code typ} header themselves in order to determine what kind of
		 * validation is needed
		 * </p>
		 *
		 * <p>
		 * This is done for you when you use {@link JwtValidators} to construct a
		 * validator.
		 *
		 * <p>
		 * That means that this: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer).build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer);
		 * </code>
		 *
		 * <p>
		 * Is equivalent to this: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
		 *     		new JwtIssuerValidator(issuer), JwtTypeValidator.jwt());
		 * </code>
		 *
		 * <p>
		 * The difference is that by setting this to {@code false}, it allows you to
		 * provide validation by type, like for {@code at+jwt}: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(new MyAtJwtValidator());
		 * </code>
		 * @param shouldValidateTypHeader whether Nimbus should validate the typ header or
		 * not
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 * @since 6.5
		 */
		// 控制是否开启对 JWT 头部 typ 字段的强校验。
		// 在 JWT 规范中，typ 头部用于声明令牌的类型（如 JWT 或 at+jwt）。开启此功能后，底层 Nimbus 库会检查该字段。如果令牌中没有 typ 或值不是 JWT，校验将失败。
		public JwkSetUriJwtDecoderBuilder validateType(boolean shouldValidateTypHeader) {
			this.typeVerifier = shouldValidateTypHeader ? JWT_TYPE_VERIFIER : NO_TYPE_VERIFIER;
			return this;
		}

		/**
		 * Append the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithm</a> to the set of algorithms to use.
		 * @param signatureAlgorithm the algorithm to use
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 */
		public JwkSetUriJwtDecoderBuilder jwsAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
			this.signatureAlgorithms.add(signatureAlgorithm);
			return this;
		}

		/**
		 * Configure the list of
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithms</a> to use with the given {@link Consumer}.
		 * @param signatureAlgorithmsConsumer a {@link Consumer} for further configuring
		 * the algorithm list
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 */
		// 允许你通过函数式编程（Consumer）的方式，直接操作内部存储签名算法的集合。
		public JwkSetUriJwtDecoderBuilder jwsAlgorithms(Consumer<Set<SignatureAlgorithm>> signatureAlgorithmsConsumer) {
			Assert.notNull(signatureAlgorithmsConsumer, "signatureAlgorithmsConsumer cannot be null");
			signatureAlgorithmsConsumer.accept(this.signatureAlgorithms);
			return this;
		}

		/**
		 * Use the given {@link RestOperations} to coordinate with the authorization
		 * servers indicated in the
		 * <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> uri as well
		 * as the <a href=
		 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a>.
		 * @param restOperations the {@link RestOperations} instance to use
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 */
		public JwkSetUriJwtDecoderBuilder restOperations(RestOperations restOperations) {
			Assert.notNull(restOperations, "restOperations cannot be null");
			this.restOperations = restOperations;
			return this;
		}

		/**
		 * Use the given {@link Cache} to store
		 * <a href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a>.
		 * @param cache the {@link Cache} to be used to store JWK Set
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 * @since 5.4
		 */
		public JwkSetUriJwtDecoderBuilder cache(Cache cache) {
			Assert.notNull(cache, "cache cannot be null");
			this.cache = cache;
			return this;
		}

		/**
		 * Use the given {@link Consumer} to customize the {@link JWTProcessor
		 * ConfigurableJWTProcessor} before passing it to the build
		 * {@link NimbusJwtDecoder}.
		 * @param jwtProcessorCustomizer the callback used to alter the processor
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 * @since 5.4
		 */
		public JwkSetUriJwtDecoderBuilder jwtProcessorCustomizer(
				Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer) {
			Assert.notNull(jwtProcessorCustomizer, "jwtProcessorCustomizer cannot be null");
			this.jwtProcessorCustomizer = jwtProcessorCustomizer;
			return this;
		}
		// 告诉解析器，在面对一个特定的 JWT 时，应该去哪里找公钥，以及允许使用哪些算法来验证签名。
		JWSKeySelector<SecurityContext> jwsKeySelector(JWKSource<SecurityContext> jwkSource) {
			// 如果开发者没有通过 .jwsAlgorithm() 手动指定算法，系统将启动自动推导。
			if (this.signatureAlgorithms.isEmpty()) {
				return new JWSVerificationKeySelector<>(this.defaultAlgorithms.apply(jwkSource), jwkSource);
			}
			Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();
			// 遍历开发者配置的白名单，将它们逐一“翻译”成 Nimbus 能听懂的格式。
			for (SignatureAlgorithm signatureAlgorithm : this.signatureAlgorithms) {
				JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
				jwsAlgorithms.add(jwsAlgorithm);
			}
			// 如果匹配，则从 jwkSource 中根据 kid 过滤出正确的公钥。
			return new JWSVerificationKeySelector<>(jwsAlgorithms, jwkSource);
		}
		// 核心任务是将 Spring 的 RestOperations 和 Cache 桥接到 Nimbus 库的 JWKSource 接口上。
		// 如果是 Issuer 自动发现 模式，它会先用 restOperations 去请求 OpenID 配置接口（.well-known/openid-configuration），从返回的 JSON 中提取出真正的 jwks_uri 地址。
		// 核心在于 JWKSourceBuilder 的配置逻辑，它将 SpringJWKSource（Spring 实现的拉取逻辑）包装成了 Nimbus 能够使用的对象：
		JWKSource<SecurityContext> jwkSource() {
			String jwkSetUri = this.jwkSetUri.apply(this.restOperations);
			return JWKSourceBuilder.create(new SpringJWKSource<>(this.restOperations, this.cache, jwkSetUri))
				.refreshAheadCache(false)
				.rateLimited(false)
				.cache(this.cache instanceof NoOpCache)
				.build();
		}
		// 任务是将之前定义的所有组件（密钥源、算法选择器、类型验证器）封装进一个 Nimbus 库的 JWTProcessor
		JWTProcessor<SecurityContext> processor() {
			JWKSource<SecurityContext> jwkSource = jwkSource();
			ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSTypeVerifier(this.typeVerifier);
			jwtProcessor.setJWSKeySelector(jwsKeySelector(jwkSource));
			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
			});
			this.jwtProcessorCustomizer.accept(jwtProcessor);
			return jwtProcessor;
		}

		/**
		 * Build the configured {@link NimbusJwtDecoder}.
		 * @return the configured {@link NimbusJwtDecoder}
		 */
		public NimbusJwtDecoder build() {
			return new NimbusJwtDecoder(processor());
		}

		private static final class SpringJWKSource<C extends SecurityContext> implements JWKSetSource<C> {

			private static final MediaType APPLICATION_JWK_SET_JSON = new MediaType("application", "jwk-set+json");

			private final ReentrantLock reentrantLock = new ReentrantLock();

			private final RestOperations restOperations;

			private final Cache cache;

			private final String jwkSetUri;

			private JWKSet jwkSet;

			private SpringJWKSource(RestOperations restOperations, Cache cache, String jwkSetUri) {
				Assert.notNull(restOperations, "restOperations cannot be null");
				this.restOperations = restOperations;
				this.cache = cache;
				this.jwkSetUri = jwkSetUri;
				String jwks = this.cache.get(this.jwkSetUri, String.class);
				if (jwks != null) {
					try {
						this.jwkSet = JWKSet.parse(jwks);
					}
					catch (ParseException ignored) {
						// Ignore invalid cache value
					}
				}
			}

			private String fetchJwks() throws Exception {
				HttpHeaders headers = new HttpHeaders();
				headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON, APPLICATION_JWK_SET_JSON));
				RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.GET, URI.create(this.jwkSetUri));
				ResponseEntity<String> response = this.restOperations.exchange(request, String.class);
				String jwks = response.getBody();
				this.jwkSet = JWKSet.parse(jwks);
				return jwks;
			}

			@Override
			public JWKSet getJWKSet(JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime, C context)
					throws KeySourceException {
				try {
					this.reentrantLock.lock();
					if (refreshEvaluator.requiresRefresh(this.jwkSet)) {
						this.cache.invalidate();
					}
					this.cache.get(this.jwkSetUri, this::fetchJwks);
					return this.jwkSet;
				}
				catch (Cache.ValueRetrievalException ex) {
					if (ex.getCause() instanceof RemoteKeySourceException keys) {
						throw keys;
					}
					throw new RemoteKeySourceException(ex.getCause().getMessage(), ex.getCause());
				}
				finally {
					this.reentrantLock.unlock();
				}
			}

			@Override
			public void close() {

			}

		}

	}

	/**
	 * A builder for creating {@link NimbusJwtDecoder} instances based on a public key.
	 */
	public static final class PublicKeyJwtDecoderBuilder {

		private static final JOSEObjectTypeVerifier<SecurityContext> JWT_TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(
				JOSEObjectType.JWT, null);

		private static final JOSEObjectTypeVerifier<SecurityContext> NO_TYPE_VERIFIER = (header, context) -> {
		};

		private JWSAlgorithm jwsAlgorithm;

		private JOSEObjectTypeVerifier<SecurityContext> typeVerifier = JWT_TYPE_VERIFIER;

		private final RSAPublicKey key;

		private Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer;

		private PublicKeyJwtDecoderBuilder(RSAPublicKey key) {
			Assert.notNull(key, "key cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.RS256;
			this.key = key;
			this.jwtProcessorCustomizer = (processor) -> {
			};
		}

		/**
		 * Whether to use Nimbus's typ header verification. This is {@code true} by
		 * default, however it may change to {@code false} in a future major release.
		 *
		 * <p>
		 * By turning off this feature, {@link NimbusJwtDecoder} expects applications to
		 * check the {@code typ} header themselves in order to determine what kind of
		 * validation is needed
		 * </p>
		 *
		 * <p>
		 * This is done for you when you use {@link JwtValidators} to construct a
		 * validator.
		 *
		 * <p>
		 * That means that this: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer).build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer);
		 * </code>
		 *
		 * <p>
		 * Is equivalent to this: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
		 *     		new JwtIssuerValidator(issuer), JwtTypeValidator.jwt());
		 * </code>
		 *
		 * <p>
		 * The difference is that by setting this to {@code false}, it allows you to
		 * provide validation by type, like for {@code at+jwt}: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(new MyAtJwtValidator());
		 * </code>
		 * @param shouldValidateTypHeader whether Nimbus should validate the typ header or
		 * not
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 * @since 6.5
		 */
		public PublicKeyJwtDecoderBuilder validateType(boolean shouldValidateTypHeader) {
			this.typeVerifier = shouldValidateTypHeader ? JWT_TYPE_VERIFIER : NO_TYPE_VERIFIER;
			return this;
		}

		/**
		 * Use the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithm</a>. The value should be one of
		 * <a href="https://tools.ietf.org/html/rfc7518#section-3.3" target=
		 * "_blank">RS256, RS384, or RS512</a>.
		 * @param signatureAlgorithm the algorithm to use
		 * @return a {@link PublicKeyJwtDecoderBuilder} for further configurations
		 */
		public PublicKeyJwtDecoderBuilder signatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
			return this;
		}

		/**
		 * Use the given {@link Consumer} to customize the {@link JWTProcessor
		 * ConfigurableJWTProcessor} before passing it to the build
		 * {@link NimbusJwtDecoder}.
		 * @param jwtProcessorCustomizer the callback used to alter the processor
		 * @return a {@link PublicKeyJwtDecoderBuilder} for further configurations
		 * @since 5.4
		 */
		public PublicKeyJwtDecoderBuilder jwtProcessorCustomizer(
				Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer) {
			Assert.notNull(jwtProcessorCustomizer, "jwtProcessorCustomizer cannot be null");
			this.jwtProcessorCustomizer = jwtProcessorCustomizer;
			return this;
		}

		JWTProcessor<SecurityContext> processor() {
			Assert.state(JWSAlgorithm.Family.RSA.contains(this.jwsAlgorithm),
					() -> "The provided key is of type RSA; however the signature algorithm is of some other type: "
							+ this.jwsAlgorithm + ". Please indicate one of RS256, RS384, or RS512.");
			JWSKeySelector<SecurityContext> jwsKeySelector = new SingleKeyJWSKeySelector<>(this.jwsAlgorithm, this.key);
			DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSTypeVerifier(this.typeVerifier);
			jwtProcessor.setJWSKeySelector(jwsKeySelector);
			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
			});
			this.jwtProcessorCustomizer.accept(jwtProcessor);
			return jwtProcessor;
		}

		/**
		 * Build the configured {@link NimbusJwtDecoder}.
		 * @return the configured {@link NimbusJwtDecoder}
		 */
		public NimbusJwtDecoder build() {
			return new NimbusJwtDecoder(processor());
		}

	}

	/**
	 * A builder for creating {@link NimbusJwtDecoder} instances based on a
	 * {@code SecretKey}.
	 */
	public static final class SecretKeyJwtDecoderBuilder {

		private static final JOSEObjectTypeVerifier<SecurityContext> JWT_TYPE_VERIFIER = new DefaultJOSEObjectTypeVerifier<>(
				JOSEObjectType.JWT, null);

		private static final JOSEObjectTypeVerifier<SecurityContext> NO_TYPE_VERIFIER = (header, context) -> {
		};

		private final SecretKey secretKey;

		private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

		private JOSEObjectTypeVerifier<SecurityContext> typeVerifier = JWT_TYPE_VERIFIER;

		private Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer;

		private SecretKeyJwtDecoderBuilder(SecretKey secretKey) {
			Assert.notNull(secretKey, "secretKey cannot be null");
			this.secretKey = secretKey;
			this.jwtProcessorCustomizer = (processor) -> {
			};
		}

		/**
		 * Whether to use Nimbus's typ header verification. This is {@code true} by
		 * default, however it may change to {@code false} in a future major release.
		 *
		 * <p>
		 * By turning off this feature, {@link NimbusJwtDecoder} expects applications to
		 * check the {@code typ} header themselves in order to determine what kind of
		 * validation is needed
		 * </p>
		 *
		 * <p>
		 * This is done for you when you use {@link JwtValidators} to construct a
		 * validator.
		 *
		 * <p>
		 * That means that this: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer).build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer);
		 * </code>
		 *
		 * <p>
		 * Is equivalent to this: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
		 *     		new JwtIssuerValidator(issuer), JwtTypeValidator.jwt());
		 * </code>
		 *
		 * <p>
		 * The difference is that by setting this to {@code false}, it allows you to
		 * provide validation by type, like for {@code at+jwt}: <code>
		 *     NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuer)
		 *         .validateType(false)
		 *         .build();
		 *     jwtDecoder.setJwtValidator(new MyAtJwtValidator());
		 * </code>
		 * @param shouldValidateTypHeader whether Nimbus should validate the typ header or
		 * not
		 * @return a {@link JwkSetUriJwtDecoderBuilder} for further configurations
		 * @since 6.5
		 */
		public SecretKeyJwtDecoderBuilder validateType(boolean shouldValidateTypHeader) {
			this.typeVerifier = shouldValidateTypHeader ? JWT_TYPE_VERIFIER : NO_TYPE_VERIFIER;
			return this;
		}

		/**
		 * Use the given
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target=
		 * "_blank">algorithm</a> when generating the MAC. The value should be one of
		 * <a href="https://tools.ietf.org/html/rfc7518#section-3.2" target=
		 * "_blank">HS256, HS384 or HS512</a>.
		 * @param macAlgorithm the MAC algorithm to use
		 * @return a {@link SecretKeyJwtDecoderBuilder} for further configurations
		 */
		public SecretKeyJwtDecoderBuilder macAlgorithm(MacAlgorithm macAlgorithm) {
			Assert.notNull(macAlgorithm, "macAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(macAlgorithm.getName());
			return this;
		}

		/**
		 * Use the given {@link Consumer} to customize the {@link JWTProcessor
		 * ConfigurableJWTProcessor} before passing it to the build
		 * {@link NimbusJwtDecoder}.
		 * @param jwtProcessorCustomizer the callback used to alter the processor
		 * @return a {@link SecretKeyJwtDecoderBuilder} for further configurations
		 * @since 5.4
		 */
		public SecretKeyJwtDecoderBuilder jwtProcessorCustomizer(
				Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer) {
			Assert.notNull(jwtProcessorCustomizer, "jwtProcessorCustomizer cannot be null");
			this.jwtProcessorCustomizer = jwtProcessorCustomizer;
			return this;
		}

		/**
		 * Build the configured {@link NimbusJwtDecoder}.
		 * @return the configured {@link NimbusJwtDecoder}
		 */
		public NimbusJwtDecoder build() {
			return new NimbusJwtDecoder(processor());
		}

		JWTProcessor<SecurityContext> processor() {
			JWSKeySelector<SecurityContext> jwsKeySelector = new SingleKeyJWSKeySelector<>(this.jwsAlgorithm,
					this.secretKey);
			DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
			jwtProcessor.setJWSKeySelector(jwsKeySelector);
			jwtProcessor.setJWSTypeVerifier(this.typeVerifier);
			// Spring Security validates the claim set independent from Nimbus
			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
			});
			this.jwtProcessorCustomizer.accept(jwtProcessor);
			return jwtProcessor;
		}

	}

}
