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

package org.springframework.security.web.authentication.switchuser;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * Custom {@code GrantedAuthority} used by
 * {@link org.springframework.security.web.authentication.switchuser.SwitchUserFilter}
 * <p>
 * Stores the {@code Authentication} object of the original user to be used later when
 * 'exiting' from a user switch.
 *
 * @author Mark St.Godard
 * @see org.springframework.security.web.authentication.switchuser.SwitchUserFilter
 */
// SwitchUserGrantedAuthority 是 Spring Security 中一个非常特殊且功能强大的类。它专门用于支持 “切换用户”（User Switching / Impersonation） 功能。
// 在很多企业级应用中，管理员需要能够“切换”到普通用户的身份来排查问题或代为操作。Spring Security 通过 SwitchUserFilter 实现这一功能。
// 核心问题：切换后，系统如何记住“谁才是真正的管理员”？以便稍后能切回管理员身份？
// 解决方案：Spring Security 会在用户 A 的权限列表（Authorities）中添加一个 SwitchUserGrantedAuthority。这个权限对象就像一个“回生符”，它内部封装了管理员原始的 Authentication 对象。
public final class SwitchUserGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	// 标识符。通常是 ROLE_PREVIOUS_ADMINISTRATOR。这让系统识别出该权限是一个“切换标记”。
	private final String role;
	// 原始身份快照。
	// 这是最重要的属性，它保存了发起切换操作的那个用户（通常是管理员）的完整认证信息。
	private final Authentication source;

	public SwitchUserGrantedAuthority(String role, Authentication source) {
		Assert.notNull(role, "role cannot be null");
		Assert.notNull(source, "source cannot be null");
		this.role = role;
		this.source = source;
	}

	/**
	 * Returns the original user associated with a successful user switch.
	 * @return The original <code>Authentication</code> object of the switched user.
	 */
	public Authentication getSource() {
		return this.source;
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
		if (obj instanceof SwitchUserGrantedAuthority swa) {
			return this.role.equals(swa.getAuthority()) && this.source.equals(swa.getSource());
		}
		return false;
	}

	@Override
	public int hashCode() {
		int result = this.role.hashCode();
		result = 31 * result + this.source.hashCode();
		return result;
	}

	@Override
	public String toString() {
		return "Switch User Authority [" + this.role + "," + this.source + "]";
	}

}
