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

import org.springframework.security.authorization.AuthorizationManager;

/**
 * Represents an authority granted to an {@link Authentication} object.
 *
 * <p>
 * A <code>GrantedAuthority</code> must either represent itself as a <code>String</code>
 * or be specifically supported by an {@link AuthorizationManager}.
 *
 * @author Ben Alex
 */
// GrantedAuthority（授予的权限）是**授权（Authorization）**模型的基础单元。如果说 Authentication 解决了“你是谁”的问题，那么 GrantedAuthority 解决的就是“你能做什么”的问题。
// GrantedAuthority 表示授予给认证主体（Principal）的一种“权力”或“许可”。
// 权限的抽象：它是一个极其简化的接口，将复杂的权限逻辑抽象为一个简单的字符串标识。
// 解耦认证与授权：通过这个接口，Spring Security 可以将用户的身份（User）与其拥有的权限（Authorities）关联起来。
// 决策依据：在请求资源（如访问某个 URL 或调用某个方法）时，AuthorizationManager（授权管理器）会检查当前用户的 Authentication 对象中是否包含匹配的 GrantedAuthority。
public interface GrantedAuthority extends Serializable {

	/**
	 * If the <code>GrantedAuthority</code> can be represented as a <code>String</code>
	 * and that <code>String</code> is sufficient in precision to be relied upon for an
	 * access control decision by an {@link AuthorizationManager} (or delegate), this
	 * method should return such a <code>String</code>.
	 * <p>
	 * If the <code>GrantedAuthority</code> cannot be expressed with sufficient precision
	 * as a <code>String</code>, <code>null</code> should be returned. Returning
	 * <code>null</code> will require an <code>AccessDecisionManager</code> (or delegate)
	 * to specifically support the <code>GrantedAuthority</code> implementation, so
	 * returning <code>null</code> should be avoided unless actually required.
	 * @return a representation of the granted authority (or <code>null</code> if the
	 * granted authority cannot be expressed as a <code>String</code> with sufficient
	 * precision).
	 */
	// 获取该权限的字符串表示形式。
	// 作为标识符：该方法返回一个字符串（如 ROLE_ADMIN、READ_PRIVILEGE）。这个字符串是授权决策的核心依据。
	String getAuthority();

}
