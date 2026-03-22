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

import org.springframework.util.Assert;

/**
 * A <code>ThreadLocal</code>-based implementation of
 * {@link SecurityContextHolderStrategy}.
 *
 * @author Ben Alex
 * @author Rob Winch
 * @see java.lang.ThreadLocal
 * @see org.springframework.security.core.context.web.SecurityContextPersistenceFilter
 */
// ThreadLocalSecurityContextHolderStrategy 是 Spring Security 最核心、也是默认使用的存储策略类。它利用 Java 的 ThreadLocal 机制，确保安全上下文（SecurityContext）在同一个线程（Thread）中是共享的，而在不同线程之间是物理隔离的。
// 在典型的 Java Web 应用中，Servlet 容器（如 Tomcat）会为每个到来的 HTTP 请求分配一个独立的线程。
// 线程隔离：它保证 A 用户请求的线程绝对看不到 B 用户请求的线程中的安全信息。
// 全局可访问性：由于信息存在线程局部变量中，开发者可以在该请求处理路径上的任何地方（Controller、Service、甚至深层的 Dao）通过 SecurityContextHolder 拿回当前登录用户的信息，而不需要通过方法参数层层传递。
// 延迟加载支持：从 Spring Security 5.8 开始，该类增强了对 Supplier 的支持，允许安全上下文在真正被需要时才进行初始化，优化了性能。
final class ThreadLocalSecurityContextHolderStrategy implements SecurityContextHolderStrategy {
	// 存放数据的“秘密抽屉”。
	private static final ThreadLocal<Supplier<SecurityContext>> contextHolder = new ThreadLocal<>();

	@Override
	public void clearContext() {
		contextHolder.remove();
	}

	@Override
	public SecurityContext getContext() {
		return getDeferredContext().get();
	}

	@Override
	public Supplier<SecurityContext> getDeferredContext() {
		Supplier<SecurityContext> result = contextHolder.get();
		if (result == null) {
			SecurityContext context = createEmptyContext();
			result = () -> context;
			contextHolder.set(result);
		}
		return result;
	}

	@Override
	public void setContext(SecurityContext context) {
		Assert.notNull(context, "Only non-null SecurityContext instances are permitted");
		contextHolder.set(() -> context);
	}

	@Override
	public void setDeferredContext(Supplier<SecurityContext> deferredContext) {
		Assert.notNull(deferredContext, "Only non-null Supplier instances are permitted");
		Supplier<SecurityContext> notNullDeferredContext = () -> {
			SecurityContext result = deferredContext.get();
			Assert.notNull(result, "A Supplier<SecurityContext> returned null and is not allowed.");
			return result;
		};
		contextHolder.set(notNullDeferredContext);
	}

	@Override
	public SecurityContext createEmptyContext() {
		return new SecurityContextImpl();
	}

}
