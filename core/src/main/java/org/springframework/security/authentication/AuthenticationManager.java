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
 * Processes an {@link Authentication} request.
 *
 * @author Ben Alex
 * @author KyeongHoon Lee
 */
// AuthenticationManager（认证管理器）是一个至关重要的中枢接口。它是连接 Web 安全层与业务认证逻辑的桥梁。
// 定义标准：它定义了 Spring Security 如何“处理认证请求”。无论你是用用户名密码登录、指纹识别还是 OAuth2，最终都会流向这个接口。
// 解耦设计：它将“如何提取请求”（Filter 层的工作）与“如何验证身份”（Provider 层的工作）彻底解耦。它不关心认证的细节，只关心结果。
// 核心实现类：在实际应用中，你遇到最多的实现类是 ProviderManager，它内部维护了一组 AuthenticationProvider 来执行具体的认证逻辑。
@FunctionalInterface
public interface AuthenticationManager {

	/**
	 * Attempts to authenticate the passed {@link Authentication} object, returning a
	 * fully populated <code>Authentication</code> object (including granted authorities)
	 * if successful.
	 * <p>
	 * An <code>AuthenticationManager</code> must honour the following contract concerning
	 * exceptions:
	 * <ul>
	 * <li>A {@link DisabledException} must be thrown if an account is disabled and the
	 * <code>AuthenticationManager</code> can test for this state.</li>
	 * <li>A {@link LockedException} must be thrown if an account is locked and the
	 * <code>AuthenticationManager</code> can test for account locking.</li>
	 * <li>A {@link BadCredentialsException} must be thrown if incorrect credentials are
	 * presented. Whilst the above exceptions are optional, an
	 * <code>AuthenticationManager</code> must <B>always</B> test credentials.</li>
	 * </ul>
	 * Exceptions should be tested for and if applicable thrown in the order expressed
	 * above (i.e. if an account is disabled or locked, the authentication request is
	 * immediately rejected and the credentials testing process is not performed). This
	 * prevents credentials being tested against disabled or locked accounts.
	 * @param authentication the authentication request object
	 * @return a fully authenticated object including credentials
	 * @throws AuthenticationException if authentication fails
	 */
	// 这是该接口唯一的方法，虽然简单，但它承载了一套极其严格的“认证契约（Contract）”。
	// 参数：接收一个 Authentication 对象。这个对象通常是“未认证”的（只有用户名和密码，没有权限列表）。
	// 返回值：如果认证成功，必须返回一个**完全填充（Fully Populated）**的 Authentication 对象。这个对象应包含：
	Authentication authenticate(Authentication authentication) throws AuthenticationException;

}
