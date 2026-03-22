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

package org.springframework.security.authentication;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * Iterates an {@link Authentication} request through a list of
 * {@link AuthenticationProvider}s.
 *
 * <p>
 * <tt>AuthenticationProvider</tt>s are usually tried in order until one provides a
 * non-null response. A non-null response indicates the provider had authority to decide
 * on the authentication request and no further providers are tried. If a subsequent
 * provider successfully authenticates the request, the earlier authentication exception
 * is disregarded and the successful authentication will be used. If no subsequent
 * provider provides a non-null response, or a new <code>AuthenticationException</code>,
 * the last <code>AuthenticationException</code> received will be used. If no provider
 * returns a non-null response, or indicates it can even process an
 * <code>Authentication</code>, the <code>ProviderManager</code> will throw a
 * <code>ProviderNotFoundException</code>. A parent {@code AuthenticationManager} can also
 * be set, and this will also be tried if none of the configured providers can perform the
 * authentication. This is intended to support namespace configuration options though and
 * is not a feature that should normally be required.
 * <p>
 * The exception to this process is when a provider throws an
 * {@link AccountStatusException}, in which case no further providers in the list will be
 * queried.
 *
 * Post-authentication, the credentials will be cleared from the returned
 * {@code Authentication} object, if it implements the {@link CredentialsContainer}
 * interface. This behaviour can be controlled by modifying the
 * {@link #setEraseCredentialsAfterAuthentication(boolean)
 * eraseCredentialsAfterAuthentication} property.
 *
 * <h2>Event Publishing</h2>
 * <p>
 * Authentication event publishing is delegated to the configured
 * {@link AuthenticationEventPublisher} which defaults to a null implementation which
 * doesn't publish events, so if you are configuring the bean yourself you must inject a
 * publisher bean if you want to receive events. The standard implementation is
 * {@link DefaultAuthenticationEventPublisher} which maps common exceptions to events (in
 * the case of authentication failure) and publishes an
 * {@link org.springframework.security.authentication.event.AuthenticationSuccessEvent
 * AuthenticationSuccessEvent} if authentication succeeds. If you are using the namespace
 * then an instance of this bean will be used automatically by the <tt>&lt;http&gt;</tt>
 * configuration, so you will receive events from the web part of your application
 * automatically.
 * <p>
 * Note that the implementation also publishes authentication failure events when it
 * obtains an authentication result (or an exception) from the "parent"
 * {@code AuthenticationManager} if one has been set. So in this situation, the parent
 * should not generally be configured to publish events or there will be duplicates.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @see DefaultAuthenticationEventPublisher
 */
// ProviderManager 是 Spring Security 中 AuthenticationManager 最常用的实现类。
// 如果说 AuthenticationManager 是认证的总入口，那么 ProviderManager 就是真正的执行调度中心。
// 它的设计理念是**“职责链模式（Chain of Responsibility）”**。
// 组合多个插件：它内部维护了一个 AuthenticationProvider 列表。
// 每个 Provider 负责一种认证方式（如：一个查数据库，一个查 LDAP，一个处理短信验证码）。
// 轮询匹配：当一个认证请求进来时，它会逐个询问这些 Provider：“你能处理这个凭证吗？”。如果能，就让该 Provider 尝试认证。
// 父级回退机制：它支持嵌套，如果当前 ProviderManager 所有的 Provider 都无法处理，它可以将请求转发给一个 Parent（父级管理器）。
// 安全清理：认证成功后，它负责擦除敏感信息（如明文密码），防止泄露。
public class ProviderManager implements AuthenticationManager, MessageSourceAware, InitializingBean {

	private static final Log logger = LogFactory.getLog(ProviderManager.class);
	// 事件发布器。负责在认证成功或失败时对外广播事件（如发送登录日志）。默认是一个空实现 NullEventPublisher。
	private AuthenticationEventPublisher eventPublisher = new NullEventPublisher();
	// 核心列表。存储了所有注册的认证执行者（如 DaoAuthenticationProvider）。
	private List<AuthenticationProvider> providers = Collections.emptyList();
	// 用于获取国际化（I18N）的错误消息。
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	// 父级管理器。通常用于实现权限的分级管理，如果本地 Providers 都没匹配上，则求助于 Parent。
	private AuthenticationManager parent;
	// 凭证擦除开关。默认为 true。认证成功后，会把 Authentication 对象里的密码设为 null 以保安全。
	private boolean eraseCredentialsAfterAuthentication = true;

	/**
	 * Construct a {@link ProviderManager} using the given {@link AuthenticationProvider}s
	 * @param providers the {@link AuthenticationProvider}s to use
	 */
	public ProviderManager(AuthenticationProvider... providers) {
		this(Arrays.asList(providers), null);
	}

	/**
	 * Construct a {@link ProviderManager} using the given {@link AuthenticationProvider}s
	 * @param providers the {@link AuthenticationProvider}s to use
	 */
	public ProviderManager(List<AuthenticationProvider> providers) {
		this(providers, null);
	}

	/**
	 * Construct a {@link ProviderManager} using the provided parameters
	 * @param providers the {@link AuthenticationProvider}s to use
	 * @param parent a parent {@link AuthenticationManager} to fall back to
	 */
	public ProviderManager(List<AuthenticationProvider> providers, AuthenticationManager parent) {
		Assert.notNull(providers, "providers list cannot be null");
		this.providers = providers;
		this.parent = parent;
		checkState();
	}

	@Override
	public void afterPropertiesSet() {
		checkState();
	}

	private void checkState() {
		Assert.isTrue(this.parent != null || !this.providers.isEmpty(),
				"A parent AuthenticationManager or a list of AuthenticationProviders is required");
		Assert.isTrue(!CollectionUtils.contains(this.providers.iterator(), null),
				"providers list cannot contain null values");
	}

	/**
	 * Attempts to authenticate the passed {@link Authentication} object.
	 * <p>
	 * The list of {@link AuthenticationProvider}s will be successively tried until an
	 * <code>AuthenticationProvider</code> indicates it is capable of authenticating the
	 * type of <code>Authentication</code> object passed. Authentication will then be
	 * attempted with that <code>AuthenticationProvider</code>.
	 * <p>
	 * If more than one <code>AuthenticationProvider</code> supports the passed
	 * <code>Authentication</code> object, the first one able to successfully authenticate
	 * the <code>Authentication</code> object determines the <code>result</code>,
	 * overriding any possible <code>AuthenticationException</code> thrown by earlier
	 * supporting <code>AuthenticationProvider</code>s. On successful authentication, no
	 * subsequent <code>AuthenticationProvider</code>s will be tried. If authentication
	 * was not successful by any supporting <code>AuthenticationProvider</code> the last
	 * thrown <code>AuthenticationException</code> will be rethrown.
	 * @param authentication the authentication request object.
	 * @return a fully authenticated object including credentials.
	 * @throws AuthenticationException if authentication fails.
	 */
	// ProviderManager 的 authenticate 方法是 Spring Security 认证流程中最能体现“设计模式”精髓的地方。
	// 它通过对一组 AuthenticationProvider 进行链式调度，实现了对多种登录方式的兼容。
	// 寻找最合适的认证执行者并获取最终的身份证明。
	// 它不仅仅是简单的循环。它有一套精密的**短路（Short-circuit）和回退（Fallback）**机制。
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Class<? extends Authentication> toTest = authentication.getClass();
		AuthenticationException lastException = null;
		AuthenticationException parentException = null;
		Authentication result = null;
		Authentication parentResult = null;
		int currentPosition = 0;
		int size = this.providers.size();
		for (AuthenticationProvider provider : getProviders()) {
			// 类型匹配 (supports)：首先判断 Provider 是否支持当前的 Token 类型（如 UsernamePasswordAuthenticationToken）。不支持则直接跳过。
			if (!provider.supports(toTest)) {
				continue;
			}
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Authenticating request with %s (%d/%d)",
						provider.getClass().getSimpleName(), ++currentPosition, size));
			}
			try {
				// 尝试认证
				result = provider.authenticate(authentication);
				if (result != null) {
					// 成功（非空）：调用 copyDetails 复制请求元数据，并执行 break 跳出循环。
					// 一旦有一个 Provider 成功，后续所有 Provider 都不再尝试。
					copyDetails(authentication, result);
					break;
				}
			}
			// 账户异常/服务内部异常：抛出 AccountStatusException 或 InternalAuthenticationServiceException。
			// 此时会立即中断整个流程并直接向上抛出异常。这是为了防止在账户已被锁定的情况下，仍然去尝试其他认证方式，从而导致安全隐患。
			catch (AccountStatusException ex) {
				prepareException(ex, authentication);
				logger.debug(LogMessage.format("Authentication failed for user '%s' since their account status is %s",
						authentication.getName(), ex.getMessage()), ex);
				// SEC-546: Avoid polling additional providers if auth failure is due to
				// invalid account status
				throw ex;
			}
			catch (InternalAuthenticationServiceException ex) {
				prepareException(ex, authentication);
				logger.debug(LogMessage.format("Authentication service failed internally for user '%s'",
						authentication.getName()), ex);
				// SEC-546: Avoid polling additional providers if auth failure is due to
				// invalid account status
				throw ex;
			}
			catch (AuthenticationException ex) {
				ex.setAuthenticationRequest(authentication);
				logger.debug(LogMessage.format("Authentication failed with provider %s since %s",
						provider.getClass().getSimpleName(), ex.getMessage()));
				lastException = ex;
			}
		}
		// 第二阶段：父级回退 (Parent Fallback)
		// 如果本地的所有 Provider 都没能给出成功的结果（返回 null 或抛出异常），代码会检查是否存在 parent 管理器。
		if (result == null && this.parent != null) {
			// Allow the parent to try.
			try {
				parentResult = this.parent.authenticate(authentication);
				result = parentResult;
			}
			catch (ProviderNotFoundException ex) {
				// ignore as we will throw below if no other exception occurred prior to
				// calling parent and the parent
				// may throw ProviderNotFound even though a provider in the child already
				// handled the request
			}
			catch (AuthenticationException ex) {
				parentException = ex;
				lastException = ex;
			}
		}
		// 第三阶段：凭证擦除 (Security Cleanup)
		if (result != null) {
			if (this.eraseCredentialsAfterAuthentication && (result instanceof CredentialsContainer)) {
				// Authentication is complete. Remove credentials and other secret data
				// from authentication
				((CredentialsContainer) result).eraseCredentials();
			}
			// If the parent AuthenticationManager was attempted and successful then it
			// will publish an AuthenticationSuccessEvent
			// This check prevents a duplicate AuthenticationSuccessEvent if the parent
			// AuthenticationManager already published it
			if (parentResult == null) {
				this.eventPublisher.publishAuthenticationSuccess(result);
			}

			return result;
		}

		// Parent was null, or didn't authenticate (or throw an exception).
		if (lastException == null) {
			lastException = new ProviderNotFoundException(this.messages.getMessage("ProviderManager.providerNotFound",
					new Object[] { toTest.getName() }, "No AuthenticationProvider found for {0}"));
		}
		// If the parent AuthenticationManager was attempted and failed then it will
		// publish an AbstractAuthenticationFailureEvent
		// This check prevents a duplicate AbstractAuthenticationFailureEvent if the
		// parent AuthenticationManager already published it
		if (parentException == null) {
			prepareException(lastException, authentication);
		}

		// Ensure this message is not logged when authentication is attempted by
		// the parent provider
		if (this.parent != null) {
			logger.debug("Denying authentication since all attempted providers failed");
		}

		throw lastException;
	}

	@SuppressWarnings("deprecation")
	private void prepareException(AuthenticationException ex, Authentication auth) {
		ex.setAuthenticationRequest(auth);
		this.eventPublisher.publishAuthenticationFailure(ex, auth);
	}

	/**
	 * Copies the authentication details from a source Authentication object to a
	 * destination one, provided the latter does not already have one set.
	 * @param source source authentication
	 * @param dest the destination authentication object
	 */
	private void copyDetails(Authentication source, Authentication dest) {
		if ((dest instanceof AbstractAuthenticationToken token) && (dest.getDetails() == null)) {
			token.setDetails(source.getDetails());
		}
	}

	public List<AuthenticationProvider> getProviders() {
		return this.providers;
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	public void setAuthenticationEventPublisher(AuthenticationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "AuthenticationEventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
	}

	/**
	 * If set to, a resulting {@code Authentication} which implements the
	 * {@code CredentialsContainer} interface will have its
	 * {@link CredentialsContainer#eraseCredentials() eraseCredentials} method called
	 * before it is returned from the {@code authenticate()} method.
	 * @param eraseSecretData set to {@literal false} to retain the credentials data in
	 * memory. Defaults to {@literal true}.
	 */
	public void setEraseCredentialsAfterAuthentication(boolean eraseSecretData) {
		this.eraseCredentialsAfterAuthentication = eraseSecretData;
	}

	public boolean isEraseCredentialsAfterAuthentication() {
		return this.eraseCredentialsAfterAuthentication;
	}

	private static final class NullEventPublisher implements AuthenticationEventPublisher {

		@Override
		public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
		}

		@Override
		public void publishAuthenticationSuccess(Authentication authentication) {
		}

	}

}
