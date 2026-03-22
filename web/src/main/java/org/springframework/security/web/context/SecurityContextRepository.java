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

package org.springframework.security.web.context;

import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.function.SingletonSupplier;

/**
 * Strategy used for persisting a {@link SecurityContext} between requests.
 * <p>
 * Used by {@link SecurityContextPersistenceFilter} to obtain the context which should be
 * used for the current thread of execution and to store the context once it has been
 * removed from thread-local storage and the request has completed.
 * <p>
 * The persistence mechanism used will depend on the implementation, but most commonly the
 * <tt>HttpSession</tt> will be used to store the context.
 *
 * @author Luke Taylor
 * @since 3.0
 * @see SecurityContextPersistenceFilter
 * @see HttpSessionSecurityContextRepository
 * @see SaveContextOnUpdateOrErrorResponseWrapper
 */
// SecurityContextRepository 是 Spring Security 中负责 “安全上下文持久化” 的核心策略接口。
// 如果说 AuthenticationManager 负责认证，那么这个类就负责在认证成功后，如何让用户在接下来的多次请求中依然保持“登录状态”。
// 它的核心职责是：在不同的 HTTP 请求之间存储和恢复 SecurityContext（安全上下文）。
// 跨请求保持状态：HTTP 本身是无状态的。该接口定义了如何把当前线程的认证信息（如存放在 HttpSession 中）拿出来，以及在请求结束时如何存回去。
// 桥接存储介质：它不限制存储位置。最常见的实现是存入 HttpSession，但在无状态架构中，也可以实现为从 Redis 或 Cookie 中读取。
// 解耦 Filter：它为 SecurityContextPersistenceFilter（老版本）或 SecurityContextHolderFilter（新版本）提供统一的操作接口，使这些过滤器不需要关心底层的存储细节。


public interface SecurityContextRepository {

	/**
	 * Obtains the security context for the supplied request. For an unauthenticated user,
	 * an empty context implementation should be returned. This method should not return
	 * null.
	 * <p>
	 * The use of the <tt>HttpRequestResponseHolder</tt> parameter allows implementations
	 * to return wrapped versions of the request or response (or both), allowing them to
	 * access implementation-specific state for the request. The values obtained from the
	 * holder will be passed on to the filter chain and also to the <tt>saveContext</tt>
	 * method when it is finally called to allow implicit saves of the
	 * <tt>SecurityContext</tt>. Implementations may wish to return a subclass of
	 * {@link SaveContextOnUpdateOrErrorResponseWrapper} as the response object, which
	 * guarantees that the context is persisted when an error or redirect occurs.
	 * Implementations may allow passing in the original request response to allow
	 * explicit saves.
	 * @param requestResponseHolder holder for the current request and response for which
	 * the context should be loaded.
	 * @return The security context which should be used for the current request, never
	 * null.
	 * @deprecated Use {@link #loadDeferredContext(HttpServletRequest)} instead.
	 */
	// 根据传入的请求/响应持有者，获取当前请求的 SecurityContext
	@Deprecated
	SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder);

	/**
	 * Defers loading the {@link SecurityContext} using the {@link HttpServletRequest}
	 * until it is needed by the application.
	 * @param request the {@link HttpServletRequest} to load the {@link SecurityContext}
	 * from
	 * @return a {@link DeferredSecurityContext} that returns the {@link SecurityContext}
	 * which cannot be null
	 * @since 5.8
	 */
	// 延迟加载安全上下文。这是 Spring Security 5.8 引入的重要优化。
	// 参数：当前的 HttpServletRequest。
	// 返回值：返回一个 DeferredSecurityContext。
	// 它不会立即去读取 Session。它返回一个“期约（Promise）”，只有当应用逻辑真正需要用户信息时，才会触发底层的读取动作。
	default DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
		Supplier<SecurityContext> supplier = () -> loadContext(new HttpRequestResponseHolder(request, null));
		return new SupplierDeferredSecurityContext(SingletonSupplier.of(supplier),
				SecurityContextHolder.getContextHolderStrategy());
	}

	/**
	 * Stores the security context on completion of a request.
	 * @param context the non-null context which was obtained from the holder.
	 * @param request
	 * @param response
	 */
	// 在请求处理完成或认证成功后，将最新的 SecurityContext 保存到持久化存储中。
	void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response);

	/**
	 * Allows the repository to be queried as to whether it contains a security context
	 * for the current request.
	 * @param request the current request
	 * @return true if a context is found for the request, false otherwise
	 */
	// 快速查询当前请求是否已经在持久化存储中关联了安全上下文。
	// true 表示存在（用户可能已登录），false 表示不存在。
	// 优化意义：在某些场景下，我们只需要知道用户“是否已登录”，而不需要解析出复杂的权限信息，这个方法可以提供高性能的探测。
	boolean containsContext(HttpServletRequest request);

}
