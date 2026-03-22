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

package org.springframework.security.oauth2.core.user;

import java.net.URL;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * A {@link GrantedAuthority} that may be associated to an {@link OAuth2User}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2User
 */
// 不仅实现了普通的权限接口，还专门为 OAuth 2.0 登录场景 设计，用于承载第三方平台（如 GitHub、Google）返回的用户详细属性。
// 在 OAuth2 登录流程中，当客户端从授权服务器获取 Access Token 后，会进一步调用 UserInfo Endpoint 获取用户信息。
// 属性持有者：它不仅代表一个权限（Authority），还持有一个 Map，存储了从 UserInfo 接口获取的原始属性（如 email, sub, picture 等）。
// 身份关联：它是 OAuth2User 的组成部分。通过它，Spring Security 可以在授权决策时，既参考用户的权限字符串，也能访问用户的详细 profile 信息。
// 灵活建模：相比于普通的 SimpleGrantedAuthority（只有一个字符串），它允许开发者在授权逻辑中利用复杂的第三方用户信息。
public class OAuth2UserAuthority implements GrantedAuthority {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	// 权限标识符。默认为 "OAUTH2_USER"。
	// 它是用于 Spring Security 权限检查（如 hasAuthority）的字符串。
	private final String authority;
	// 用户属性集。存储从授权服务器返回的键值对。
	// 它是不可变的（Unmodifiable），保证了数据安全性。
	private final Map<String, Object> attributes;
	// 主键属性名。标识 attributes 映射中哪个键（Key）代表用户的“唯一标识”或“登录名”（例如 sub 或 id）。
	private final String userNameAttributeName;

	/**
	 * Constructs a {@code OAuth2UserAuthority} using the provided parameters and defaults
	 * {@link #getAuthority()} to {@code OAUTH2_USER}.
	 * @param attributes the attributes about the user
	 */
	public OAuth2UserAuthority(Map<String, Object> attributes) {
		this("OAUTH2_USER", attributes);
	}

	/**
	 * Constructs a {@code OAuth2UserAuthority} using the provided parameters and defaults
	 * {@link #getAuthority()} to {@code OAUTH2_USER}.
	 * @param attributes the attributes about the user
	 * @param userNameAttributeName the attribute name used to access the user's name from
	 * the attributes
	 * @since 6.4
	 */
	public OAuth2UserAuthority(Map<String, Object> attributes, @Nullable String userNameAttributeName) {
		this("OAUTH2_USER", attributes, userNameAttributeName);
	}

	/**
	 * Constructs a {@code OAuth2UserAuthority} using the provided parameters.
	 * @param authority the authority granted to the user
	 * @param attributes the attributes about the user
	 */
	public OAuth2UserAuthority(String authority, Map<String, Object> attributes) {
		this(authority, attributes, null);
	}

	/**
	 * Constructs a {@code OAuth2UserAuthority} using the provided parameters.
	 * @param authority the authority granted to the user
	 * @param attributes the attributes about the user
	 * @param userNameAttributeName the attribute name used to access the user's name from
	 * the attributes
	 * @since 6.4
	 */
	public OAuth2UserAuthority(String authority, Map<String, Object> attributes, String userNameAttributeName) {
		Assert.hasText(authority, "authority cannot be empty");
		Assert.notEmpty(attributes, "attributes cannot be empty");
		this.authority = authority;
		this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
		this.userNameAttributeName = userNameAttributeName;
	}

	@Override
	public String getAuthority() {
		return this.authority;
	}

	/**
	 * Returns the attributes about the user.
	 * @return a {@code Map} of attributes about the user
	 */
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	/**
	 * Returns the attribute name used to access the user's name from the attributes.
	 * @return the attribute name used to access the user's name from the attributes
	 * @since 6.4
	 */
	@Nullable
	public String getUserNameAttributeName() {
		return this.userNameAttributeName;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}
		OAuth2UserAuthority that = (OAuth2UserAuthority) obj;
		if (!this.getAuthority().equals(that.getAuthority())) {
			return false;
		}
		Map<String, Object> thatAttributes = that.getAttributes();
		if (getAttributes().size() != thatAttributes.size()) {
			return false;
		}
		for (Map.Entry<String, Object> e : getAttributes().entrySet()) {
			String key = e.getKey();
			Object value = convertURLIfNecessary(e.getValue());
			if (value == null) {
				if (!(thatAttributes.get(key) == null && thatAttributes.containsKey(key))) {
					return false;
				}
			}
			else {
				Object thatValue = convertURLIfNecessary(thatAttributes.get(key));
				if (!value.equals(thatValue)) {
					return false;
				}
			}
		}
		return true;
	}

	@Override
	public int hashCode() {
		int result = this.getAuthority().hashCode();
		result = 31 * result;
		for (Map.Entry<String, Object> e : getAttributes().entrySet()) {
			Object key = e.getKey();
			Object value = convertURLIfNecessary(e.getValue());
			result += Objects.hashCode(key) ^ Objects.hashCode(value);
		}
		return result;
	}

	@Override
	public String toString() {
		return this.getAuthority();
	}

	/**
	 * @return {@code URL} converted to a string since {@code URL} shouldn't be used for
	 * equality/hashCode. For other instances the value is returned as is.
	 */
	private static Object convertURLIfNecessary(Object value) {
		return (value instanceof URL) ? ((URL) value).toExternalForm() : value;
	}

}
