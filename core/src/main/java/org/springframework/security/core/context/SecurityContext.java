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

package org.springframework.security.core.context;

import java.io.Serializable;

import org.springframework.security.core.Authentication;

/**
 * Interface defining the minimum security information associated with the current thread
 * of execution.
 *
 * <p>
 * The security context is stored in a {@link SecurityContextHolder}.
 * </p>
 *
 * @author Ben Alex
 */
// SecurityContext 的主要作用是存储和获取当前执行线程的安全细节。
// 关联当前线程：在典型的 Servlet 应用中，每个请求由一个线程处理。Spring Security 会将 SecurityContext 与当前线程绑定。
// 持有认证主体：它是 Authentication 对象的直接容器。无论是在 Controller、Service 还是工具类中，只要你能访问到这个上下文，你就能知道“当前是谁在访问系统”。
// 解耦业务与安全：业务代码不需要关注登录信息是从 Session、JWT 还是 OAuth2 来的，只需要从 SecurityContext 中“取”出 Authentication 即可。
public interface SecurityContext extends Serializable {

	/**
	 * Obtains the currently authenticated principal, or an authentication request token.
	 * @return the <code>Authentication</code> or <code>null</code> if no authentication
	 * information is available
	 */
	// 获取当前认证通过的主体（Principal）或认证请求令牌（Token）。
	Authentication getAuthentication();

	/**
	 * Changes the currently authenticated principal, or removes the authentication
	 * information.
	 * @param authentication the new <code>Authentication</code> token, or
	 * <code>null</code> if no further authentication information should be stored
	 */
	// 更改当前认证的主体信息，或清除认证信息。
	void setAuthentication(Authentication authentication);

}
