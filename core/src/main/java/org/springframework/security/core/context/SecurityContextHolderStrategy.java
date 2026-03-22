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

import java.util.function.Supplier;

/**
 * A strategy for storing security context information against a thread.
 *
 * <p>
 * The preferred strategy is loaded by {@link SecurityContextHolder}.
 *
 * @author Ben Alex
 * @author Rob Winch
 */
// 如果说 SecurityContext 是存放认证信息的“保险箱”，那么 SecurityContextHolderStrategy 就是规定这个保险箱该放在哪里的“存放策略”。
// 在不同的应用环境下，存储安全上下文（SecurityContext）的方式是不一样的：
// 标准 Web 应用：每个请求由一个独立线程处理，通常存在 ThreadLocal 里。
// 胖客户端应用（Swing/JavaFX）：整个应用可能共用一个身份，需要全局存储。
// 异步/多线程应用：需要父线程将身份传给子线程（InheritableThreadLocal）。
public interface SecurityContextHolderStrategy {

	/**
	 * Clears the current context.
	 */
	// 完全清除当前环境中的安全信息。
	void clearContext();

	/**
	 * Obtains the current context.
	 * @return a context (never <code>null</code> - create a default implementation if
	 * necessary)
	 */
	// 获取当前环境（通常是当前线程）下的 SecurityContext。
	// 要求：实现类必须保证该方法永不返回 null。
	SecurityContext getContext();

	/**
	 * Obtains a {@link Supplier} that returns the current context.
	 * @return a {@link Supplier} that returns the current context (never
	 * <code>null</code> - create a default implementation if necessary)
	 * @since 5.8
	 */
	// 获取一个用于返回 SecurityContext 的延迟加载提供者（Supplier）。
	// 设计目的：提升性能。在某些场景下（比如某些 Filter 只是想看看有没有上下文但不立即操作），通过 Supplier 可以实现延迟加载，直到真正需要 Authentication 时才触发底层的检索逻辑。
	default Supplier<SecurityContext> getDeferredContext() {
		return this::getContext;
	}

	/**
	 * Sets the current context.
	 * @param context to the new argument (should never be <code>null</code>, although
	 * implementations must check if <code>null</code> has been passed and throw an
	 * <code>IllegalArgumentException</code> in such cases)
	 */
	// 将指定的 SecurityContext 存入当前环境。
	void setContext(SecurityContext context);

	/**
	 * Sets a {@link Supplier} that will return the current context. Implementations can
	 * override the default to avoid invoking {@link Supplier#get()}.
	 * @param deferredContext a {@link Supplier} that returns the {@link SecurityContext}
	 * @since 5.8
	 */
	// 设置一个延迟加载的 SecurityContext 供应源。
	default void setDeferredContext(Supplier<SecurityContext> deferredContext) {
		setContext(deferredContext.get());
	}

	/**
	 * Creates a new, empty context implementation, for use by
	 * <tt>SecurityContextRepository</tt> implementations, when creating a new context for
	 * the first time.
	 * @return the empty context.
	 */
	// 创建一个全新的、空的 SecurityContext 实例。
	SecurityContext createEmptyContext();

}
