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

package org.springframework.security.authentication;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is
 * designed for simple presentation of a username and password.
 * <p>
 * The <code>principal</code> and <code>credentials</code> should be set with an
 * <code>Object</code> that provides the respective property via its
 * <code>Object.toString()</code> method. The simplest such <code>Object</code> to use is
 * <code>String</code>.
 *
 * @author Ben Alex
 * @author Norbert Nowak
 */
// UsernamePasswordAuthenticationToken 是 Spring Security 中最核心、使用频率最高的认证实现类。它专门为传统的“用户名+密码”登录模式设计，承载了从用户提交凭证到系统确认身份的完整数据流。
// 这个类扮演了 Authentication（认证对象） 的角色，在认证流程中具有双重身份：
// 认证请求的容器：当用户在表单输入用户名和密码点击登录时，Filter 会创建一个该类的实例（此时标记为“未认证”），里面只装着用户名和密码。
// 认证成功的证据：一旦 DaoAuthenticationProvider 验证密码正确，它会创建一个新的该类实例（此时标记为“已认证”），里面装着完整的用户信息（UserDetails）和权限列表（Authorities）。
public class UsernamePasswordAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	// 主体。在认证前，它通常是用户输入的 String 类型的用户名；认证成功后，它通常是 UserDetails 实现类对象。
	private final Object principal;
	// 凭证。通常是用户输入的明文密码。为了安全，认证成功后此属性通常会被置为 null。
	private Object credentials;

	/**
	 * This constructor can be safely used by any code that wishes to create a
	 * <code>UsernamePasswordAuthenticationToken</code>, as the {@link #isAuthenticated()}
	 * will return <code>false</code>.
	 *
	 */
	public UsernamePasswordAuthenticationToken(Object principal, Object credentials) {
		super(null);
		this.principal = principal;
		this.credentials = credentials;
		setAuthenticated(false);
	}

	/**
	 * This constructor should only be used by <code>AuthenticationManager</code> or
	 * <code>AuthenticationProvider</code> implementations that are satisfied with
	 * producing a trusted (i.e. {@link #isAuthenticated()} = <code>true</code>)
	 * authentication token.
	 * @param principal
	 * @param credentials
	 * @param authorities
	 */
	public UsernamePasswordAuthenticationToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		super.setAuthenticated(true); // must use super, as we override
	}

	/**
	 * This factory method can be safely used by any code that wishes to create a
	 * unauthenticated <code>UsernamePasswordAuthenticationToken</code>.
	 * @param principal
	 * @param credentials
	 * @return UsernamePasswordAuthenticationToken with false isAuthenticated() result
	 *
	 * @since 5.7
	 */
	public static UsernamePasswordAuthenticationToken unauthenticated(Object principal, Object credentials) {
		return new UsernamePasswordAuthenticationToken(principal, credentials);
	}

	/**
	 * This factory method can be safely used by any code that wishes to create a
	 * authenticated <code>UsernamePasswordAuthenticationToken</code>.
	 * @param principal
	 * @param credentials
	 * @return UsernamePasswordAuthenticationToken with true isAuthenticated() result
	 *
	 * @since 5.7
	 */
	public static UsernamePasswordAuthenticationToken authenticated(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		return new UsernamePasswordAuthenticationToken(principal, credentials, authorities);
	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated,
				"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.credentials = null;
	}

}
