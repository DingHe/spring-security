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

package org.springframework.security.authentication.jaas;

import java.security.Principal;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * {@code GrantedAuthority} which, in addition to the assigned role, holds the principal
 * that an {@link AuthorityGranter} used as a reason to grant this authority.
 *
 * @author Ray Krueger
 * @see AuthorityGranter
 */
// JaasGrantedAuthority 是 Spring Security 为集成 JAAS (Java Authentication and Authorization Service) 专门设计的一个权限类。
// 它属于 GrantedAuthority 的一种特殊实现。
// 在标准的 Java 安全体系中，JAAS 认证通过后会产生一个 Subject，其中包含多个 Principal（身份主体）。
// 关联起因：Spring Security 使用 AuthorityGranter 接口将 JAAS 的 Principal 转换为 Spring Security 的 GrantedAuthority（权限）。
// 持有“授信证据”：与普通的 SimpleGrantedAuthority 不同，JaasGrantedAuthority 不仅保存了权限字符串（如 ROLE_ADMIN），还保存了导致该权限被授予的那个 Principal 对象。
// 可追溯性：它让开发者能够知道：“这个用户之所以拥有这个角色，是因为他在 JAAS 中拥有这个特定的身份标识”。
public final class JaasGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	// 权限名/角色名。这是 Spring Security 进行授权检查（如 hasRole）时使用的字符串标识。
	private final String role;
	// 关联主体。这是触发该权限生成的 JAAS 原始 Principal 对象。它是“为什么授予这个权限”的证据。
	private final Principal principal;

	public JaasGrantedAuthority(String role, Principal principal) {
		Assert.notNull(role, "role cannot be null");
		Assert.notNull(principal, "principal cannot be null");
		this.role = role;
		this.principal = principal;
	}

	public Principal getPrincipal() {
		return this.principal;
	}

	@Override
	public String getAuthority() {
		return this.role;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj instanceof JaasGrantedAuthority jga) {
			return this.role.equals(jga.getAuthority()) && this.principal.equals(jga.getPrincipal());
		}
		return false;
	}

	@Override
	public int hashCode() {
		int result = this.principal.hashCode();
		result = 31 * result + this.role.hashCode();
		return result;
	}

	@Override
	public String toString() {
		return "Jaas Authority [" + this.role + "," + this.principal + "]";
	}

}
