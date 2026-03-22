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

package org.springframework.security.ldap.userdetails;

import java.io.Serial;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * An authority that contains at least a DN and a role name for an LDAP entry but can also
 * contain other desired attributes to be fetched during an LDAP authority search.
 *
 * @author Filip Hanik
 */
// LdapAuthority 是一个专门为 LDAP（轻量级目录访问协议） 认证场景设计的权限类。
// 它不仅包含基本的权限字符串，还保留了 LDAP 条目的元数据。
// 当使用 LDAP 进行认证和授权时，权限（Authorities）通常映射自 LDAP 中的组（Groups）或特定属性。
// 身份与路径绑定：普通的权限类只保存一个名字（如 ROLE_ADMIN），但 LdapAuthority 还保存了该权限在 LDAP 目录中的 DN（Distinguished Name，区分名称）。这对于需要知道权限来源路径的场景非常有用。
// 属性携带者：除了角色名，它还可以携带从 LDAP 条目中抓取的额外属性（如 mail、uid、memberOf 等）。
// 丰富的上下文：它让开发者在进行授权决策时，不仅能看到“用户有什么角色”，还能看到该角色在 LDAP 树中的位置以及相关的条目详情。
public class LdapAuthority implements GrantedAuthority {

	@Serial
	private static final long serialVersionUID = 343193700821611354L;
	// 区分名称。表示该权限条目在 LDAP 树中的完整路径（例如：cn=managers,ou=groups,dc=example,dc=com）。
	private final String dn;
	// 角色名称。即 Spring Security 最终用于匹配的权限字符串（例如：ROLE_ADMIN）。
	private final String role;
	// LDAP 属性集。一个键值对集合，存储了该 LDAP 条目的其他属性。由于 LDAP 属性可以是多值的，所以 Value 使用了 List<String>。
	private final Map<String, List<String>> attributes;

	/**
	 * Constructs an LdapAuthority that has a role and a DN but no other attributes
	 * @param role the principal's role
	 * @param dn the distinguished name
	 */
	public LdapAuthority(String role, String dn) {
		this(role, dn, null);
	}

	/**
	 * Constructs an LdapAuthority with the given role, DN and other LDAP attributes
	 * @param role the principal's role
	 * @param dn the distinguished name
	 * @param attributes additional LDAP attributes
	 */
	public LdapAuthority(String role, String dn, Map<String, List<String>> attributes) {
		Assert.notNull(role, "role can not be null");
		Assert.notNull(dn, "dn can not be null");
		this.role = role;
		this.dn = dn;
		this.attributes = attributes;
	}

	/**
	 * Returns the LDAP attributes
	 * @return the LDAP attributes, map can be null
	 */
	public Map<String, List<String>> getAttributes() {
		return this.attributes;
	}

	/**
	 * Returns the DN for this LDAP authority
	 * @return the distinguished name
	 */
	public String getDn() {
		return this.dn;
	}

	/**
	 * Returns the values for a specific attribute
	 * @param name the attribute name
	 * @return a String array, never null but may be zero length
	 */
	public List<String> getAttributeValues(String name) {
		List<String> result = null;
		if (this.attributes != null) {
			result = this.attributes.get(name);
		}
		return (result != null) ? result : Collections.emptyList();
	}

	/**
	 * Returns the first attribute value for a specified attribute
	 * @param name the attribute name
	 * @return the first attribute value for a specified attribute, may be null
	 */
	public String getFirstAttributeValue(String name) {
		List<String> result = getAttributeValues(name);
		return (!result.isEmpty()) ? result.get(0) : null;
	}

	@Override
	public String getAuthority() {
		return this.role;
	}

	/**
	 * Compares the LdapAuthority based on {@link #getAuthority()} and {@link #getDn()}
	 * values.
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof LdapAuthority other)) {
			return false;
		}
		if (!this.dn.equals(other.getDn())) {
			return false;
		}
		return this.role.equals(other.getAuthority());
	}

	@Override
	public int hashCode() {
		int result = this.dn.hashCode();
		result = 31 * result + ((this.role != null) ? this.role.hashCode() : 0);
		return result;
	}

	@Override
	public String toString() {
		return "LdapAuthority{" + "dn='" + this.dn + '\'' + ", role='" + this.role + '\'' + '}';
	}

}
