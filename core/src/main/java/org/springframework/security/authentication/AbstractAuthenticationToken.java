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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * Base class for <code>Authentication</code> objects.
 * <p>
 * Implementations which use this class should be immutable.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
// AbstractAuthenticationToken 是 Spring Security 认证体系中最重要的基类之一。
// 它实现了 Authentication 接口，为所有的认证令牌（Tokens）提供了通用的基础结构。
// 在 Spring Security 中，几乎所有的认证实现（如用户名密码、JWT、OAuth2、记住我）都继承自这个类。
// 减少重复代码：它实现了 Authentication 接口中大部分通用的逻辑（如权限管理、认证状态标记、详细信息处理等），让具体的子类只需关注 getPrincipal() 和 getCredentials()。
// 安全保护：通过实现 CredentialsContainer 接口，它提供了一个标准的方法来擦除敏感信息（如密码），防止密码长时间驻留在内存中。
// 规范化标识：它定义了如何从不同的主体对象（UserDetails, Principal 等）中提取用户名称。
public abstract class AbstractAuthenticationToken implements Authentication, CredentialsContainer {
	// 权限集合。
	// 存储用户拥有的角色或权限。一旦初始化，通常被设置为不可变，以保证安全性。
	private final Collection<GrantedAuthority> authorities;
	// 额外细节。通常用于存储 Web 请求相关的上下文（如 IP 地址、Session ID 等）。
	private Object details;
	// 认证状态。默认为 false。只有当认证管理器验证通过后，才会将其设为 true。
	private boolean authenticated = false;

	/**
	 * Creates a token with the supplied array of authorities.
	 * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
	 * represented by this authentication object.
	 */
	public AbstractAuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
		if (authorities == null) {
			this.authorities = AuthorityUtils.NO_AUTHORITIES;
			return;
		}
		for (GrantedAuthority a : authorities) {
			Assert.notNull(a, "Authorities collection cannot contain any null elements");
		}
		this.authorities = Collections.unmodifiableList(new ArrayList<>(authorities));
	}
	// 获取授予主体的权限。
	// 构造时确定的不可变权限集合。
	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}
	// 从主体（Principal）中提取并返回用户名称。
	@Override
	public String getName() {
		if (this.getPrincipal() instanceof UserDetails userDetails) {
			return userDetails.getUsername();
		}
		if (this.getPrincipal() instanceof AuthenticatedPrincipal authenticatedPrincipal) {
			return authenticatedPrincipal.getName();
		}
		if (this.getPrincipal() instanceof Principal principal) {
			return principal.getName();
		}
		return (this.getPrincipal() == null) ? "" : this.getPrincipal().toString();
	}
	// 获取或设置当前的认证状态。
	@Override
	public boolean isAuthenticated() {
		return this.authenticated;
	}
	// 获取或设置当前的认证状态。
	@Override
	public void setAuthenticated(boolean authenticated) {
		this.authenticated = authenticated;
	}
	// 存取认证请求之外的附加信息。子类通常在 Filter 层通过 AuthenticationDetailsSource 注入这些数据。
	@Override
	public Object getDetails() {
		return this.details;
	}

	public void setDetails(Object details) {
		this.details = details;
	}

	/**
	 * Checks the {@code credentials}, {@code principal} and {@code details} objects,
	 * invoking the {@code eraseCredentials} method on any which implement
	 * {@link CredentialsContainer}.
	 */
	@Override
	public void eraseCredentials() {
		eraseSecret(getCredentials());
		eraseSecret(getPrincipal());
		eraseSecret(this.details);
	}

	private void eraseSecret(Object secret) {
		if (secret instanceof CredentialsContainer container) {
			container.eraseCredentials();
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AbstractAuthenticationToken test)) {
			return false;
		}
		if (!this.authorities.equals(test.authorities)) {
			return false;
		}
		if ((this.details == null) && (test.getDetails() != null)) {
			return false;
		}
		if ((this.details != null) && (test.getDetails() == null)) {
			return false;
		}
		if ((this.details != null) && (!this.details.equals(test.getDetails()))) {
			return false;
		}
		if ((this.getCredentials() == null) && (test.getCredentials() != null)) {
			return false;
		}
		if ((this.getCredentials() != null) && !this.getCredentials().equals(test.getCredentials())) {
			return false;
		}
		if (this.getPrincipal() == null && test.getPrincipal() != null) {
			return false;
		}
		if (this.getPrincipal() != null && !this.getPrincipal().equals(test.getPrincipal())) {
			return false;
		}
		return this.isAuthenticated() == test.isAuthenticated();
	}

	@Override
	public int hashCode() {
		int code = 31;
		for (GrantedAuthority authority : this.authorities) {
			code ^= authority.hashCode();
		}
		if (this.getPrincipal() != null) {
			code ^= this.getPrincipal().hashCode();
		}
		if (this.getCredentials() != null) {
			code ^= this.getCredentials().hashCode();
		}
		if (this.getDetails() != null) {
			code ^= this.getDetails().hashCode();
		}
		if (this.isAuthenticated()) {
			code ^= -37;
		}
		return code;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(getClass().getSimpleName()).append(" [");
		sb.append("Principal=").append(getPrincipal()).append(", ");
		sb.append("Credentials=[PROTECTED], ");
		sb.append("Authenticated=").append(isAuthenticated()).append(", ");
		sb.append("Details=").append(getDetails()).append(", ");
		sb.append("Granted Authorities=").append(this.authorities);
		sb.append("]");
		return sb.toString();
	}

}
