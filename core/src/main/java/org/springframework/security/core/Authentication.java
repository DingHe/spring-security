/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Represents the token for an authentication request or for an authenticated principal
 * once the request has been processed by the
 * {@link AuthenticationManager#authenticate(Authentication)} method.
 * <p>
 * Once the request has been authenticated, the <tt>Authentication</tt> will usually be
 * stored in a thread-local <tt>SecurityContext</tt> managed by the
 * {@link SecurityContextHolder} by the authentication mechanism which is being used. An
 * explicit authentication can be achieved, without using one of Spring Security's
 * authentication mechanisms, by creating an <tt>Authentication</tt> instance and using
 * the code:
 *
 * <pre>
 * SecurityContext context = SecurityContextHolder.createEmptyContext();
 * context.setAuthentication(anAuthentication);
 * SecurityContextHolder.setContext(context);
 * </pre>
 *
 * Note that unless the <tt>Authentication</tt> has the <tt>authenticated</tt> property
 * set to <tt>true</tt>, it will still be authenticated by any security interceptor (for
 * method or web invocations) which encounters it.
 * <p>
 * In most cases, the framework transparently takes care of managing the security context
 * and authentication objects for you.
 *
 * @author Ben Alex
 */
// Authentication 接口是整个安全框架的核心数据模型。它不仅代表了“登录用户”的身份，还贯穿了从“发起登录请求”到“完成授权校验”的全生命周期。
// Authentication 主要承担以下三个核心角色：
// 认证请求的载体 (Token)：当用户尝试登录时，系统会将用户提交的凭证（如用户名/密码）封装进一个 Authentication 实现类中（如 UsernamePasswordAuthenticationToken），交给 AuthenticationManager 进行校验。
// 已认证实体的代表：一旦认证成功，AuthenticationManager 会返回一个包含用户详细信息、权限列表且标记为“已认证”的 Authentication 对象。
// 安全上下文的核心：认证后的对象会被存入 SecurityContextHolder。后续系统在进行权限检查（授权）时，会从这里调取用户的权限列表。
// 它继承了 Principal（代表身份主体）和 Serializable（支持序列化，方便存入 Redis 等 Session 存储）。
public interface Authentication extends Principal, Serializable {

	/**
	 * Set by an <code>AuthenticationManager</code> to indicate the authorities that the
	 * principal has been granted. Note that classes should not rely on this value as
	 * being valid unless it has been set by a trusted <code>AuthenticationManager</code>.
	 * <p>
	 * Implementations should ensure that modifications to the returned collection array
	 * do not affect the state of the Authentication object, or use an unmodifiable
	 * instance.
	 * </p>
	 * @return the authorities granted to the principal, or an empty collection if the
	 * token has not been authenticated. Never null.
	 */
	// 获取当前用户被授予的权限集合。
	// 返回一个 GrantedAuthority 的集合。这些权限通常以 ROLE_USER、ROLE_ADMIN 或具体的权限字符串（如 READ_PRIVILEGE）形式存在。
	Collection<? extends GrantedAuthority> getAuthorities();

	/**
	 * The credentials that prove the principal is correct. This is usually a password,
	 * but could be anything relevant to the <code>AuthenticationManager</code>. Callers
	 * are expected to populate the credentials.
	 * @return the credentials that prove the identity of the <code>Principal</code>
	 */
	// 获取证明身份正确的凭证。
	// 通常是指密码。但在不同的认证方式中，它可能是证书、指纹信息或验证码。
	// 为了安全起见，许多实现类会在认证完成后通过 CredentialsContainer.eraseCredentials() 方法将此处的密码擦除，以防内存泄露导致密码被窃取。
	Object getCredentials();

	/**
	 * Stores additional details about the authentication request. These might be an IP
	 * address, certificate serial number etc.
	 * @return additional details about the authentication request, or <code>null</code>
	 * if not used
	 */
	// 获取关于认证请求的额外细节。
	// 这些信息不属于核心身份凭证，但对安全审计很有用。常见的内容包括：用户的 IP 地址、Session ID、或者是证书序列号。
	Object getDetails();

	/**
	 * The identity of the principal being authenticated. In the case of an authentication
	 * request with username and password, this would be the username. Callers are
	 * expected to populate the principal for an authentication request.
	 * <p>
	 * The <tt>AuthenticationManager</tt> implementation will often return an
	 * <tt>Authentication</tt> containing richer information as the principal for use by
	 * the application. Many of the authentication providers will create a
	 * {@code UserDetails} object as the principal.
	 * @return the <code>Principal</code> being authenticated or the authenticated
	 * principal after authentication.
	 */
	// 获取被认证的主体身份。
	// 认证前：通常是用户输入的“用户名”。
	// 认证后：通常是一个更丰富的对象，如 Spring Security 提供的 UserDetails 实例，其中包含用户名、账号是否锁定、密码过期等详细状态。
	Object getPrincipal();

	/**
	 * Used to indicate to {@code AbstractSecurityInterceptor} whether it should present
	 * the authentication token to the <code>AuthenticationManager</code>. Typically an
	 * <code>AuthenticationManager</code> (or, more often, one of its
	 * <code>AuthenticationProvider</code>s) will return an immutable authentication token
	 * after successful authentication, in which case that token can safely return
	 * <code>true</code> to this method. Returning <code>true</code> will improve
	 * performance, as calling the <code>AuthenticationManager</code> for every request
	 * will no longer be necessary.
	 * <p>
	 * For security reasons, implementations of this interface should be very careful
	 * about returning <code>true</code> from this method unless they are either
	 * immutable, or have some way of ensuring the properties have not been changed since
	 * original creation.
	 * @return true if the token has been authenticated and the
	 * <code>AbstractSecurityInterceptor</code> does not need to present the token to the
	 * <code>AuthenticationManager</code> again for re-authentication.
	 */
	// 判断该 Token 是否已经过认证。
	// 返回 false：表示这还只是一个认证请求，或者是一个匿名的访问请求，安全拦截器需要将其交给 AuthenticationManager 处理。
	// 返回 true：表示该对象已经过信任的认证机构验证，不需要再次认证，可以直接用于后续的授权检查。
	boolean isAuthenticated();

	/**
	 * See {@link #isAuthenticated()} for a full description.
	 * <p>
	 * Implementations should <b>always</b> allow this method to be called with a
	 * <code>false</code> parameter, as this is used by various classes to specify the
	 * authentication token should not be trusted. If an implementation wishes to reject
	 * an invocation with a <code>true</code> parameter (which would indicate the
	 * authentication token is trusted - a potential security risk) the implementation
	 * should throw an {@link IllegalArgumentException}.
	 * @param isAuthenticated <code>true</code> if the token should be trusted (which may
	 * result in an exception) or <code>false</code> if the token should not be trusted
	 * @throws IllegalArgumentException if an attempt to make the authentication token
	 * trusted (by passing <code>true</code> as the argument) is rejected due to the
	 * implementation being immutable or implementing its own alternative approach to
	 * {@link #isAuthenticated()}
	 */
	// 手动设置认证状态。
	// 设为 false：这是最常见的用法，用于使当前的认证信息失效。
	void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;

}
