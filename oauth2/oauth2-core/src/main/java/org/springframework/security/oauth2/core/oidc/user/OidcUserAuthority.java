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

package org.springframework.security.oauth2.core.oidc.user;

import java.io.Serial;
import java.util.HashMap;
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.Assert;

/**
 * A {@link GrantedAuthority} that may be associated to an {@link OidcUser}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OidcUser
 */
// OidcUserAuthority 是 Spring Security OAuth2/OIDC 模块中专为 OpenID Connect (OIDC) 1.0 协议设计的类。
// 它继承自 OAuth2UserAuthority，是 OIDC 登录场景下表示用户权限和身份信息的标准载体。
// 在 OIDC 协议中，身份认证的结果不仅仅是一个 Access Token，还包含一个 ID Token（包含用户身份声明的 JWT）。
// 身份声明的集大成者：它不仅包含普通的 OAuth2 属性，还专门封装了 OidcIdToken（必选）和 OidcUserInfo（可选）。
// 权限标记：默认赋予用户 OIDC_USER 权限。
// 声明合并：它通过静态工具方法将来自 ID Token 和 UserInfo 端点的所有声明（Claims）合并到一个统一的 Map 中，方便后续进行权限判定或页面展示。
public class OidcUserAuthority extends OAuth2UserAuthority {

	@Serial
	private static final long serialVersionUID = -4675866280835753141L;
	// 核心属性（必填）。
	// 代表 OIDC 的 ID Token，包含签发者、受众、过期时间以及用户的基本身份信息（如 sub）。
	private final OidcIdToken idToken;
	// 可选属性。如果客户端调用了 UserInfo 端点，则该属性包含更详细的用户资料（如姓名、地址、电话等）。
	private final OidcUserInfo userInfo;

	/**
	 * Constructs a {@code OidcUserAuthority} using the provided parameters.
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 */
	public OidcUserAuthority(OidcIdToken idToken) {
		this(idToken, null);
	}

	/**
	 * Constructs a {@code OidcUserAuthority} using the provided parameters and defaults
	 * {@link #getAuthority()} to {@code OIDC_USER}.
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 */
	public OidcUserAuthority(OidcIdToken idToken, OidcUserInfo userInfo) {
		this("OIDC_USER", idToken, userInfo);
	}

	/**
	 * Constructs a {@code OidcUserAuthority} using the provided parameters and defaults
	 * {@link #getAuthority()} to {@code OIDC_USER}.
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 * @param userNameAttributeName the attribute name used to access the user's name from
	 * the attributes
	 * @since 6.4
	 */
	public OidcUserAuthority(OidcIdToken idToken, OidcUserInfo userInfo, @Nullable String userNameAttributeName) {
		this("OIDC_USER", idToken, userInfo, userNameAttributeName);
	}

	/**
	 * Constructs a {@code OidcUserAuthority} using the provided parameters.
	 * @param authority the authority granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 */
	public OidcUserAuthority(String authority, OidcIdToken idToken, OidcUserInfo userInfo) {
		this(authority, idToken, userInfo, IdTokenClaimNames.SUB);
	}

	/**
	 * Constructs a {@code OidcUserAuthority} using the provided parameters.
	 * @param authority the authority granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 * @param userNameAttributeName the attribute name used to access the user's name from
	 * the attributes
	 * @since 6.4
	 */
	public OidcUserAuthority(String authority, OidcIdToken idToken, OidcUserInfo userInfo,
			@Nullable String userNameAttributeName) {
		super(authority, collectClaims(idToken, userInfo), userNameAttributeName);
		this.idToken = idToken;
		this.userInfo = userInfo;
	}

	/**
	 * Returns the {@link OidcIdToken ID Token} containing claims about the user.
	 * @return the {@link OidcIdToken} containing claims about the user.
	 */
	public OidcIdToken getIdToken() {
		return this.idToken;
	}

	/**
	 * Returns the {@link OidcUserInfo UserInfo} containing claims about the user, may be
	 * {@code null}.
	 * @return the {@link OidcUserInfo} containing claims about the user, or {@code null}
	 */
	public OidcUserInfo getUserInfo() {
		return this.userInfo;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}
		if (!super.equals(obj)) {
			return false;
		}
		OidcUserAuthority that = (OidcUserAuthority) obj;
		if (!this.getIdToken().equals(that.getIdToken())) {
			return false;
		}
		return (this.getUserInfo() != null) ? this.getUserInfo().equals(that.getUserInfo())
				: that.getUserInfo() == null;
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + this.getIdToken().hashCode();
		result = 31 * result + ((this.getUserInfo() != null) ? this.getUserInfo().hashCode() : 0);
		return result;
	}

	static Map<String, Object> collectClaims(OidcIdToken idToken, OidcUserInfo userInfo) {
		Assert.notNull(idToken, "idToken cannot be null");
		Map<String, Object> claims = new HashMap<>();
		if (userInfo != null) {
			claims.putAll(userInfo.getClaims());
		}
		claims.putAll(idToken.getClaims());
		return claims;
	}

}
