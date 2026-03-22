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

package org.springframework.security.web;

import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Defines a filter chain which is capable of being matched against an
 * {@code HttpServletRequest}. in order to decide whether it applies to that request.
 * <p>
 * Used to configure a {@code FilterChainProxy}.
 *
 * @author Luke Taylor
 * @since 3.1
 */
// 在 Spring Security 的 Web 安全架构中，SecurityFilterChain（安全过滤器链）是配置层与执行层之间的桥梁。
// 它是 Spring Security 能够对不同 URL 应用不同安全策略的核心原因。
// 多链架构的核心：Spring Security 允许存在多个 SecurityFilterChain。例如，你可以定义一个链专门处理 /api/**（使用 JWT 认证），另一个链处理 /admin/**（使用表单登录）。
// 请求分流：当一个 HTTP 请求到达服务器时，FilterChainProxy（安全总代理）会遍历所有的 SecurityFilterChain，询问：“这个请求归你管吗？”
// 解耦配置：它将“哪些请求需要保护”与“如何保护（具体的 Filter 逻辑）”封装在一起。
public interface SecurityFilterChain {
	// 判断当前的 HTTP 请求是否适用于本过滤器链。
	// 返回值：如果返回 true，则 Spring Security 会停止匹配后续的链，并直接执行本链中的所有过滤器；如果返回 false，则继续匹配下一个 SecurityFilterChain。
	boolean matches(HttpServletRequest request);
	// 获取该链中包含的所有 Servlet 过滤器（Filter）列表。
	List<Filter> getFilters();

}
