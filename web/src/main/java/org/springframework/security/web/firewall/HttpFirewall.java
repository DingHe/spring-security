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

package org.springframework.security.web.firewall;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Interface which can be used to reject potentially dangerous requests and/or wrap them
 * to control their behaviour.
 * <p>
 * The implementation is injected into the {@code FilterChainProxy} and will be invoked
 * before sending any request through the filter chain. It can also provide a response
 * wrapper if the response behaviour should also be restricted.
 *
 * @author Luke Taylor
 */
// 在 Spring Security 的 Web 安全防护体系中，HttpFirewall（HTTP 防火墙）位于最外层。它是请求进入 Spring Security 过滤器链之前的第一道关卡。
// HttpFirewall 的核心任务是在安全检查开始之前，拦截并拒绝潜在危险的请求。
// 防止规范化攻击：拦截包含特殊字符（如 ./、../、// 或 %00 等）的恶意 URL，这些字符常被用于目录遍历或绕过安全限制。
// 请求清洗与封装：如果请求虽然可疑但可以被修正，防火墙可以对其进行封装，确保后续的过滤器（如 RequestMatcher）处理的是一个“标准”且“安全”的请求对象。
// 响应增强：它同样可以封装响应对象，以限制响应的行为（例如防止某些头部信息的泄露）。
// 执行位置：它被注入到 FilterChainProxy 中，在所有 SecurityFilterChain 执行之前被调用。
public interface HttpFirewall {

	/**
	 * Provides the request object which will be passed through the filter chain.
	 * @throws RequestRejectedException if the request should be rejected immediately
	 */
	// 原始的 HTTP 请求进行安全检查，并返回一个“防火墙保护下”的请求对象。
	FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException;

	/**
	 * Provides the response which will be passed through the filter chain.
	 * @param response the original response
	 * @return either the original response or a replacement/wrapper.
	 */
	// 提供一个经过防火墙封装的响应对象。
	HttpServletResponse getFirewalledResponse(HttpServletResponse response);

}
