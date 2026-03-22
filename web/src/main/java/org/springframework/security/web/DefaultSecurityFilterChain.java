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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.BeanNameAware;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.lang.NonNull;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

/**
 * Standard implementation of {@code SecurityFilterChain}.
 *
 * @author Luke Taylor
 * @author Jinwoo Bae
 * @since 3.1
 */
// DefaultSecurityFilterChain 是 Spring Security 中 SecurityFilterChain 接口的标准且唯一的生产级实现类。它负责将一组具体的过滤器（Filters）与特定的请求匹配规则（RequestMatcher）绑定在一起。
// 路径与逻辑的绑定：它明确了“什么样的请求（URL、HTTP 方法等）”应该触发“哪些安全检查”。
// 配置的落地：你在配置类中通过 http.authorizeHttpRequests(...).build() 生成的对象，其本质就是一个 DefaultSecurityFilterChain 实例。
// 可插拔性：Spring Security 可以同时存在多个 DefaultSecurityFilterChain。例如，一个用于 API 接口（匹配 /api/**），一个用于后台管理（匹配 /admin/**），每个链包含的过滤器种类和顺序各不相同。
public final class DefaultSecurityFilterChain implements SecurityFilterChain, BeanNameAware, BeanFactoryAware {

	private static final Log logger = LogFactory.getLog(DefaultSecurityFilterChain.class);
	// 匹配决策器。定义了该链的适用范围（如 /api/**）。
	private final RequestMatcher requestMatcher;
	// 过滤器集合。存储了该链包含的所有具体安全过滤器。
	private final List<Filter> filters;
	// 该 Bean 在 Spring 容器中的名称（由 BeanNameAware 自动注入）。
	private String beanName;
	// Spring 容器工厂引用，用于在 toString 方法中获取 Bean 的定义来源，方便调试
	private ConfigurableListableBeanFactory beanFactory;

	public DefaultSecurityFilterChain(RequestMatcher requestMatcher, Filter... filters) {
		this(requestMatcher, Arrays.asList(filters));
	}

	public DefaultSecurityFilterChain(RequestMatcher requestMatcher, List<Filter> filters) {
		if (filters.isEmpty()) {
			logger.debug(LogMessage.format("Will not secure %s", requestMatcher));
		}
		else {
			List<String> filterNames = new ArrayList<>();
			for (Filter filter : filters) {
				filterNames.add(filter.getClass().getSimpleName());
			}
			String names = StringUtils.collectionToDelimitedString(filterNames, ", ");
			logger.debug(LogMessage.format("Will secure %s with filters: %s", requestMatcher, names));
		}
		this.requestMatcher = requestMatcher;
		this.filters = new ArrayList<>(filters);
	}

	public RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	@Override
	public List<Filter> getFilters() {
		return this.filters;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		return this.requestMatcher.matches(request);
	}

	@Override
	public String toString() {
		List<String> filterNames = new ArrayList<>();
		for (Filter filter : this.filters) {
			String name = filter.getClass().getSimpleName();
			if (name.endsWith("Filter")) {
				name = name.substring(0, name.length() - "Filter".length());
			}
			filterNames.add(name);
		}
		String declaration = this.getClass().getSimpleName();
		if (this.beanName != null) {
			declaration += " defined as '" + this.beanName + "'";
			if (this.beanFactory != null) {
				BeanDefinition bd = this.beanFactory.getBeanDefinition(this.beanName);
				String description = bd.getResourceDescription();
				if (description != null) {
					declaration += " in [" + description + "]";
				}
			}
		}
		return declaration + " matching [" + this.requestMatcher + "] and having filters " + filterNames;
	}

	@Override
	public void setBeanName(@NonNull String name) {
		this.beanName = name;
	}

	@Override
	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		if (beanFactory instanceof ConfigurableListableBeanFactory listable) {
			this.beanFactory = listable;
		}
	}

}
