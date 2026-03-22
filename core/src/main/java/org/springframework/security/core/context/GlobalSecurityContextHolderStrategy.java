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

import org.springframework.util.Assert;

/**
 * A <code>static</code> field-based implementation of
 * {@link SecurityContextHolderStrategy}.
 * <p>
 * This means that all instances in the JVM share the same <code>SecurityContext</code>.
 * This is generally useful with rich clients, such as Swing.
 *
 * @author Ben Alex
 */
// GlobalSecurityContextHolderStrategy 是 Spring Security 提供的另一种存储策略实现。与默认的 ThreadLocal 策略完全不同，它采用的是全局共享模式。
// 这个类的设计目标是打破线程隔离。
// 全局共享：它使用一个静态变量来存储 SecurityContext。这意味着在同一个 JVM（Java 虚拟机）进程中，无论你有多少个线程，它们访问到的都是同一个安全上下文。
// 富客户端应用：如 Swing 或 JavaFX 桌面程序。这类程序通常只有一个用户在操作，不需要像 Web 服务器那样为成千上万个并发请求区分身份。
// 单用户任务：某些特定的命令行工具或单机脚本。
// 局限性：绝对不能用于典型的 Web 应用。如果 Web 应用使用了此策略，只要有一个人登录，系统内所有其他人的请求都会自动获得该用户的身份，造成严重的安全事故。
final class GlobalSecurityContextHolderStrategy implements SecurityContextHolderStrategy {

	private static SecurityContext contextHolder;

	@Override
	public void clearContext() {
		contextHolder = null;
	}

	@Override
	public SecurityContext getContext() {
		if (contextHolder == null) {
			contextHolder = new SecurityContextImpl();
		}
		return contextHolder;
	}

	@Override
	public void setContext(SecurityContext context) {
		Assert.notNull(context, "Only non-null SecurityContext instances are permitted");
		contextHolder = context;
	}

	@Override
	public SecurityContext createEmptyContext() {
		return new SecurityContextImpl();
	}

}
