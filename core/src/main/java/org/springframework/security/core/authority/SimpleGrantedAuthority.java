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

package org.springframework.security.core.authority;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * Basic concrete implementation of a {@link GrantedAuthority}.
 *
 * <p>
 * Stores a {@code String} representation of an authority granted to the
 * {@link org.springframework.security.core.Authentication Authentication} object.
 *
 * @author Luke Taylor
 */
// SimpleGrantedAuthority 是 Spring Security 中最常用、最基础的权限实现类。它通过一个简单的字符串来表达用户的权限或角色。
// 权限原子化：它将复杂的权限逻辑简化为一个“字符串标签”。
// 通用性：它是 Spring Security 默认使用的权限载体。无论是从数据库加载的用户角色（如 ROLE_ADMIN），还是从 JWT 解析出的权限（如 READ_PRIVILEGE），通常都会被封装成 SimpleGrantedAuthority 对象。
// 不可变性：该类被设计为 final 且属性不可变，确保了权限信息在多线程环境（如并发请求处理）下的安全性。
public final class SimpleGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	// 核心属性。
	// 存储权限的文本表示。虽然变量名叫做 role，但它既可以表示角色（如 ROLE_USER），也可以表示具体权限（如 FILE_WRITE）。
	private final String role;

	public SimpleGrantedAuthority(String role) {
		Assert.hasText(role, "A granted authority textual representation is required");
		this.role = role;
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
		if (obj instanceof SimpleGrantedAuthority sga) {
			return this.role.equals(sga.getAuthority());
		}
		return false;
	}

	@Override
	public int hashCode() {
		return this.role.hashCode();
	}

	@Override
	public String toString() {
		return this.role;
	}

}
