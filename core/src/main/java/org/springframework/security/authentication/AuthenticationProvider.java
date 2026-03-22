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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Indicates a class can process a specific
 * {@link org.springframework.security.core.Authentication} implementation.
 *
 * @author Ben Alex
 */
// 如果说 ProviderManager 是认证流程的调度员，那么 AuthenticationProvider 就是真正干活的执行者。在 Spring Security 的架构中，它是一个高度可扩展的接口，定义了具体的认证逻辑。
// AuthenticationProvider 的核心作用是针对特定类型的身份凭证（Token）执行具体的认证逻辑。
// 垂直分工：不同的实现类处理不同的登录方式。例如 DaoAuthenticationProvider 处理用户名/密码，JwtAuthenticationProvider 处理 JWT 令牌。
// 解耦认证源：它屏蔽了底层的存储细节。无论用户信息是在数据库、LDAP 还是远程第三方接口，只需实现一个 Provider 即可。
// 运行时决策：它配合 ProviderManager 工作，通过自荐（supports 方法）的方式决定是否由自己来处理当前的请求。
public interface AuthenticationProvider {

	/**
	 * Performs authentication with the same contract as
	 * {@link org.springframework.security.authentication.AuthenticationManager#authenticate(Authentication)}
	 * .
	 * @param authentication the authentication request object.
	 * @return a fully authenticated object including credentials. May return
	 * <code>null</code> if the <code>AuthenticationProvider</code> is unable to support
	 * authentication of the passed <code>Authentication</code> object. In such a case,
	 * the next <code>AuthenticationProvider</code> that supports the presented
	 * <code>Authentication</code> class will be tried.
	 * @throws AuthenticationException if authentication fails.
	 */
	// 执行实际的身份验证逻辑。
	Authentication authenticate(Authentication authentication) throws AuthenticationException;

	/**
	 * Returns <code>true</code> if this <Code>AuthenticationProvider</code> supports the
	 * indicated <Code>Authentication</code> object.
	 * <p>
	 * Returning <code>true</code> does not guarantee an
	 * <code>AuthenticationProvider</code> will be able to authenticate the presented
	 * <code>Authentication</code> object. It simply indicates it can support closer
	 * evaluation of it. An <code>AuthenticationProvider</code> can still return
	 * <code>null</code> from the {@link #authenticate(Authentication)} method to indicate
	 * another <code>AuthenticationProvider</code> should be tried.
	 * </p>
	 * <p>
	 * Selection of an <code>AuthenticationProvider</code> capable of performing
	 * authentication is conducted at runtime the <code>ProviderManager</code>.
	 * </p>
	 * @param authentication
	 * @return <code>true</code> if the implementation can more closely evaluate the
	 * <code>Authentication</code> class presented
	 */
	// 告知调度器（ProviderManager）该实现类是否支持处理某种特定类型的 Authentication 对象。
	boolean supports(Class<?> authentication);

}
