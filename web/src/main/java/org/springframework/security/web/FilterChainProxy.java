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

package org.springframework.security.web;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.HttpStatusRequestRejectedHandler;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.RequestRejectedHandler;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Delegates {@code Filter} requests to a list of Spring-managed filter beans. As of
 * version 2.0, you shouldn't need to explicitly configure a {@code FilterChainProxy} bean
 * in your application context unless you need very fine control over the filter chain
 * contents. Most cases should be adequately covered by the default
 * {@code <security:http />} namespace configuration options.
 * <p>
 * The {@code FilterChainProxy} is linked into the servlet container filter chain by
 * adding a standard Spring {@link DelegatingFilterProxy} declaration in the application
 * {@code web.xml} file.
 *
 * <h2>Configuration</h2>
 * <p>
 * As of version 3.1, {@code FilterChainProxy} is configured using a list of
 * {@link SecurityFilterChain} instances, each of which contains a {@link RequestMatcher}
 * and a list of filters which should be applied to matching requests. Most applications
 * will only contain a single filter chain, and if you are using the namespace, you don't
 * have to set the chains explicitly. If you require finer-grained control, you can make
 * use of the {@code <filter-chain>} namespace element. This defines a URI pattern and the
 * list of filters (as comma-separated bean names) which should be applied to requests
 * which match the pattern. An example configuration might look like this:
 *
 * <pre>
 *  &lt;bean id="myfilterChainProxy" class="org.springframework.security.web.FilterChainProxy"&gt;
 *      &lt;constructor-arg&gt;
 *          &lt;util:list&gt;
 *              &lt;security:filter-chain pattern="/do/not/filter*" filters="none"/&gt;
 *              &lt;security:filter-chain pattern="/**" filters="filter1,filter2,filter3"/&gt;
 *          &lt;/util:list&gt;
 *      &lt;/constructor-arg&gt;
 *  &lt;/bean&gt;
 * </pre>
 *
 * The names "filter1", "filter2", "filter3" should be the bean names of {@code Filter}
 * instances defined in the application context. The order of the names defines the order
 * in which the filters will be applied. As shown above, use of the value "none" for the
 * "filters" can be used to exclude a request pattern from the security filter chain
 * entirely. Please consult the security namespace schema file for a full list of
 * available configuration options.
 *
 * <h2>Request Handling</h2>
 * <p>
 * Each possible pattern that the {@code FilterChainProxy} should service must be entered.
 * The first match for a given request will be used to define all of the {@code Filter}s
 * that apply to that request. This means you must put most specific matches at the top of
 * the list, and ensure all {@code Filter}s that should apply for a given matcher are
 * entered against the respective entry. The {@code FilterChainProxy} will not iterate
 * through the remainder of the map entries to locate additional {@code Filter}s.
 * <p>
 * {@code FilterChainProxy} respects normal handling of {@code Filter}s that elect not to
 * call
 * {@link jakarta.servlet.Filter#doFilter(jakarta.servlet.ServletRequest, jakarta.servlet.ServletResponse, jakarta.servlet.FilterChain)}
 * , in that the remainder of the original or {@code FilterChainProxy}-declared filter
 * chain will not be called.
 *
 * <h3>Request Firewalling</h3>
 *
 * An {@link HttpFirewall} instance is used to validate incoming requests and create a
 * wrapped request which provides consistent path values for matching against. See
 * {@link StrictHttpFirewall}, for more information on the type of attacks which the
 * default implementation protects against. A custom implementation can be injected to
 * provide stricter control over the request contents or if an application needs to
 * support certain types of request which are rejected by default.
 * <p>
 * Note that this means that you must use the Spring Security filters in combination with
 * a {@code FilterChainProxy} if you want this protection. Don't define them explicitly in
 * your {@code web.xml} file.
 * <p>
 * {@code FilterChainProxy} will use the firewall instance to obtain both request and
 * response objects which will be fed down the filter chain, so it is also possible to use
 * this functionality to control the functionality of the response. When the request has
 * passed through the security filter chain, the {@code reset} method will be called. With
 * the default implementation this means that the original values of {@code servletPath}
 * and {@code pathInfo} will be returned thereafter, instead of the modified ones used for
 * security pattern matching.
 * <p>
 * Since this additional wrapping functionality is performed by the
 * {@code FilterChainProxy}, we don't recommend that you use multiple instances in the
 * same filter chain. It shouldn't be considered purely as a utility for wrapping filter
 * beans in a single {@code Filter} instance.
 *
 * <h2>Filter Lifecycle</h2>
 * <p>
 * Note the {@code Filter} lifecycle mismatch between the servlet container and IoC
 * container. As described in the {@link DelegatingFilterProxy} Javadocs, we recommend you
 * allow the IoC container to manage the lifecycle instead of the servlet container.
 * {@code FilterChainProxy} does not invoke the standard filter lifecycle methods on any
 * filter beans that you add to the application context.
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 * @author Luke Taylor
 * @author Rob Winch
 */
// FilterChainProxy 是 Spring Security 的核心枢纽。它本质上是一个特殊的 Servlet Filter，负责将请求分发给一组由 Spring 管理的 Security Filter Chains。
// FilterChainProxy 是 Spring Security 过滤机制的入口点。
// 桥接作用：它作为 Web 容器（如 Tomcat）和 Spring 应用上下文之间的桥梁。通常由 DelegatingFilterProxy 拦截请求并转发给它。
// 路由分发：它持有一个 SecurityFilterChain 列表。当请求到达时，它会遍历这些链，通过 RequestMatcher 匹配当前请求，并决定使用哪一组过滤器。
// 安全防护（Firewall）：在执行任何安全过滤之前，它通过 HttpFirewall 对请求进行校验，防止常见的 Web 攻击（如 HTTP 响应拆分、路径穿越等）。
// 清理上下文：负责在请求结束后清理 SecurityContext，防止线程重用导致的信息泄露。
public class FilterChainProxy extends GenericFilterBean {

	private static final Log logger = LogFactory.getLog(FilterChainProxy.class);
	// 用于在 ServletRequest 中设置属性标签，确保 FilterChainProxy 在同一次请求中只执行一次（防止重复过滤）。
	private static final String FILTER_APPLIED = FilterChainProxy.class.getName().concat(".APPLIED");
	// 定义如何存储和访问 SecurityContext。
	// 默认使用全局的 SecurityContextHolder 策略。
	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();
	// 核心属性。
	// 包含应用中定义的所有安全过滤链。每个链包含匹配规则和对应的过滤器列表。
	private List<SecurityFilterChain> filterChains;
	// 校验器。在应用启动时检查配置的过滤器链是否合法（默认实现为空）。
	private FilterChainValidator filterChainValidator = new NullFilterChainValidator();
	// 防火墙。默认为 StrictHttpFirewall。
	// 用于包装原始请求/响应，过滤恶意字符或格式异常的请求。
	private HttpFirewall firewall = new StrictHttpFirewall();
	// 处理器。
	// 当防火墙拒绝一个请求时，由它决定返回什么响应（默认返回 403 或相关错误码）。
	private RequestRejectedHandler requestRejectedHandler = new HttpStatusRequestRejectedHandler();
	// 异常分析工具。
	// 用于从异常链中提取特定的异常（如防火墙抛出的异常）。
	private ThrowableAnalyzer throwableAnalyzer = new ThrowableAnalyzer();
	// 过滤器链装饰器（Spring Security 6.0 引入）。
	// 负责将安全过滤器列表封装成一个可执行的 FilterChain。
	private FilterChainDecorator filterChainDecorator = new VirtualFilterChainDecorator();

	public FilterChainProxy() {
	}

	public FilterChainProxy(SecurityFilterChain chain) {
		this(Arrays.asList(chain));
	}

	public FilterChainProxy(List<SecurityFilterChain> filterChains) {
		this.filterChains = filterChains;
	}
	// 在 Bean 属性设置完成后执行。调用 filterChainValidator 来验证配置是否正确。
	@Override
	public void afterPropertiesSet() {
		this.filterChainValidator.validate(this);
	}
	// 不仅仅是简单地转发请求，还承担了重入控制、异常拦截和资源清理三大职责。
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// 防止重复过滤 (Re-entry Control)
		// 确保了 Spring Security 的逻辑在一次请求中只触发一次，避免重复的认证检查或防火墙处理。如果已执行过，则直接跳过后续的清理逻辑，只执行内部过滤。
		boolean clearContext = request.getAttribute(FILTER_APPLIED) == null;
		if (!clearContext) {
			doFilterInternal(request, response, chain);
			return;
		}
		try {
			request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
			doFilterInternal(request, response, chain);
		}
		catch (Exception ex) {
			Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
			Throwable requestRejectedException = this.throwableAnalyzer
				.getFirstThrowableOfType(RequestRejectedException.class, causeChain);
			if (!(requestRejectedException instanceof RequestRejectedException)) {
				throw ex;
			}
			this.requestRejectedHandler.handle((HttpServletRequest) request, (HttpServletResponse) response,
					(RequestRejectedException) requestRejectedException);
		}
		finally {
			this.securityContextHolderStrategy.clearContext();
			request.removeAttribute(FILTER_APPLIED);
		}
	}
	// 核心调度逻辑。
	// 如果说 doFilter 是外部的防护壳，那么 doFilterInternal 就是内部的指挥官，负责决定请求应该经过哪些安全过滤器。
	private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// 调用 HttpFirewall 将原始请求和响应包装成 FirewalledRequest 和 FirewalledResponse。
		// 规范化 URL：防止路径穿越攻击（如 /a/../b 变成 /b）。
		// 安全性校验：拦截包含非法字符（如换行符、分号、控制字符）的恶意请求。
		// 一致性：确保后续匹配路径时，无论容器（Tomcat, Jetty）如何解析，Spring Security 看到的路径是一致的。
		FirewalledRequest firewallRequest = this.firewall.getFirewalledRequest((HttpServletRequest) request);
		HttpServletResponse firewallResponse = this.firewall.getFirewalledResponse((HttpServletResponse) response);
		// 获取匹配的过滤器列表 (Path Matching)
		// 根据当前请求的 URL、方法（GET/POST）等信息，找到第一个匹配的 SecurityFilterChain，并提取其中的所有 Filter。
		List<Filter> filters = getFilters(firewallRequest);
		// 情况 A：没有匹配的安全过滤器
		if (filters == null || filters.isEmpty()) {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.of(() -> "No security for " + requestLine(firewallRequest)));
			}
			// 非常重要。防火墙在包装请求时可能会修改（规范化）路径，在离开 Spring Security 作用域进入业务代码前，必须恢复原始请求的状态，以免影响后续 Servlet 的路径映射。
			firewallRequest.reset();
			// 直接跳过安全过滤，执行容器原本的过滤器链（originalChain）。
			this.filterChainDecorator.decorate(chain).doFilter(firewallRequest, firewallResponse);
			return;
		}
		if (logger.isDebugEnabled()) {
			logger.debug(LogMessage.of(() -> "Securing " + requestLine(firewallRequest)));
		}
		// 情况 B：执行安全过滤链
		// 定义了当所有安全过滤器都执行完毕（且没有被拦截）后，程序应该做什么。
		// 确保在执行具体的业务逻辑（如 Controller）之前，先重置防火墙状态，然后把控制权交回给 Servlet 容器的原始 chain。
		FilterChain reset = (req, res) -> {
			if (logger.isDebugEnabled()) {
				logger.debug(LogMessage.of(() -> "Secured " + requestLine(firewallRequest)));
			}
			// Deactivate path stripping as we exit the security filter chain
			firewallRequest.reset(); // 离开安全过滤链时重置请求
			chain.doFilter(req, res); // 执行原始的 Servlet 过滤器链
		};
		this.filterChainDecorator.decorate(reset, filters).doFilter(firewallRequest, firewallResponse);
	}

	/**
	 * Returns the first filter chain matching the supplied URL.
	 * @param request the request to match
	 * @return an ordered array of Filters defining the filter chain
	 */
	// 在众多的安全配置中，找到最适合当前请求的那一个。
	private List<Filter> getFilters(HttpServletRequest request) {
		int count = 0;
		for (SecurityFilterChain chain : this.filterChains) {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Trying to match request against %s (%d/%d)", chain, ++count,
						this.filterChains.size()));
			}
			// 匹配判定 (chain.matches)：每个 SecurityFilterChain 内部都有一个 RequestMatcher。它会检查当前请求的 URL 路径、HTTP 方法（GET/POST/等）、甚至是 Header 或 IP 地址 是否符合该链的定义。
			// 短路返回 (Short-circuit)：一旦发现第一个匹配的过滤链，方法立即返回该链包含的过滤器列表（List<Filter>），不再继续向下匹配。
			// 这就是为什么在 Spring Security 配置中，必须将“更具体的路径”（如 /api/admin/**）放在“更通用的路径”（如 /**）之前的原因。
			if (chain.matches(request)) {
				return chain.getFilters();
			}
		}
		return null;
	}

	/**
	 * Convenience method, mainly for testing.
	 * @param url the URL
	 * @return matching filter list
	 */
	public List<Filter> getFilters(String url) {
		return getFilters(this.firewall.getFirewalledRequest(new FilterInvocation(url, "GET").getRequest()));
	}

	/**
	 * @return the list of {@code SecurityFilterChain}s which will be matched against and
	 * applied to incoming requests.
	 */
	public List<SecurityFilterChain> getFilterChains() {
		return Collections.unmodifiableList(this.filterChains);
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	/**
	 * Used (internally) to specify a validation strategy for the filters in each
	 * configured chain.
	 * @param filterChainValidator the validator instance which will be invoked on during
	 * initialization to check the {@code FilterChainProxy} instance.
	 */
	public void setFilterChainValidator(FilterChainValidator filterChainValidator) {
		this.filterChainValidator = filterChainValidator;
	}

	/**
	 * Used to decorate the original {@link FilterChain} for each request
	 *
	 * <p>
	 * By default, this decorates the filter chain with a {@link VirtualFilterChain} that
	 * iterates through security filters and then delegates to the original chain
	 * @param filterChainDecorator the strategy for constructing the filter chain
	 * @since 6.0
	 */
	public void setFilterChainDecorator(FilterChainDecorator filterChainDecorator) {
		Assert.notNull(filterChainDecorator, "filterChainDecorator cannot be null");
		this.filterChainDecorator = filterChainDecorator;
	}

	/**
	 * Sets the "firewall" implementation which will be used to validate and wrap (or
	 * potentially reject) the incoming requests. The default implementation should be
	 * satisfactory for most requirements.
	 * @param firewall
	 */
	public void setFirewall(HttpFirewall firewall) {
		this.firewall = firewall;
	}

	/**
	 * Sets the {@link RequestRejectedHandler} to be used for requests rejected by the
	 * firewall.
	 * @param requestRejectedHandler the {@link RequestRejectedHandler}
	 * @since 5.2
	 */
	public void setRequestRejectedHandler(RequestRejectedHandler requestRejectedHandler) {
		Assert.notNull(requestRejectedHandler, "requestRejectedHandler may not be null");
		this.requestRejectedHandler = requestRejectedHandler;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("FilterChainProxy[");
		sb.append("Filter Chains: ");
		sb.append(this.filterChains);
		sb.append("]");
		return sb.toString();
	}

	private static String requestLine(HttpServletRequest request) {
		return request.getMethod() + " " + UrlUtils.buildRequestUrl(request);
	}

	/**
	 * Internal {@code FilterChain} implementation that is used to pass a request through
	 * the additional internal list of filters which match the request.
	 */
	// 在标准的 Servlet 容器（如 Tomcat）中，一个请求通常只对应一个过滤器映射。但 Spring Security 需要按顺序执行几十个安全过滤器（认证、授权、CSRF 防护等）。
	// 虚拟化编排：它模拟了 Servlet 容器的 FilterChain 行为，在一个逻辑链条中串联起所有的 additionalFilters（安全过滤器）。
	// 桥接业务逻辑：它充当了“先锋队”，确保所有安全检查全部通过后，才将控制权交给 originalChain（即真正的业务逻辑或 Spring MVC 的 DispatcherServlet）。
	// 状态追踪：它内部维护了一个指针，记录当前执行到了第几个过滤器，确保每个过滤器都能正确地通过 chain.doFilter() 触发下一个。
	private static final class VirtualFilterChain implements FilterChain {
		// 原始链。指向 Servlet 容器原生的过滤器链。它是安全检查结束后的终点。
		private final FilterChain originalChain;
		// 安全过滤器列表。存储了当前请求匹配到的所有 Spring Security 内部过滤器。
		private final List<Filter> additionalFilters;
		// 安全过滤器的总数量。用于判断何时结束安全检查。
		private final int size;
		// 游标/指针。记录当前正在执行第几个过滤器，初始值为 0。
		private int currentPosition = 0;

		private VirtualFilterChain(FilterChain chain, List<Filter> additionalFilters) {
			this.originalChain = chain;
			this.additionalFilters = additionalFilters;
			this.size = additionalFilters.size();
		}

		@Override
		public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
			if (this.currentPosition == this.size) {
				this.originalChain.doFilter(request, response);
				return;
			}
			this.currentPosition++;
			Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
			if (logger.isTraceEnabled()) {
				String name = nextFilter.getClass().getSimpleName();
				logger.trace(LogMessage.format("Invoking %s (%d/%d)", name, this.currentPosition, this.size));
			}
			nextFilter.doFilter(request, response, this);
		}

	}

	public interface FilterChainValidator {

		void validate(FilterChainProxy filterChainProxy);

	}

	private static class NullFilterChainValidator implements FilterChainValidator {

		@Override
		public void validate(FilterChainProxy filterChainProxy) {
		}

	}

	/**
	 * A strategy for decorating the provided filter chain with one that accounts for the
	 * {@link SecurityFilterChain} for a given request.
	 *
	 * @author Josh Cummings
	 * @since 6.0
	 */
	// 主要用于定义如何将 Spring Security 的过滤器（Security Filters）与 Servlet 容器原始的过滤器链（Original FilterChain）混合编排。
	// 在 Spring Security 的传统实现中，安全过滤器通常被封装在 VirtualFilterChain 中执行。但在某些复杂的 Web 架构中，我们需要更灵活地控制“安全滤网”是如何套在“原始请求”上的。
	// 装饰者模式的应用：它的核心作用是装饰（Decorate）。它接收原始的 FilterChain，并将 Spring Security 的一组 Filter 注入其中，返回一个新的、具备安全能力的过滤器链。
	// 架构解耦：它允许 Spring Security 在不同的 Web 容器或环境下，以不同的方式组装过滤器链。
	public interface FilterChainDecorator {

		/**
		 * Provide a new {@link FilterChain} that accounts for needed security
		 * considerations when there are no security filters.
		 * @param original the original {@link FilterChain}
		 * @return a security-enabled {@link FilterChain}
		 */
		// 提供一个没有任何安全过滤器、但仍需考虑安全因素的装饰链。
		default FilterChain decorate(FilterChain original) {
			return decorate(original, Collections.emptyList());
		}

		/**
		 * Provide a new {@link FilterChain} that accounts for the provided filters as
		 * well as the original filter chain.
		 * @param original the original {@link FilterChain}
		 * @param filters the security filters
		 * @return a security-enabled {@link FilterChain} that includes the provided
		 * filters
		 */
		// 核心装饰方法，将指定的安全过滤器注入到原始链中。
		FilterChain decorate(FilterChain original, List<Filter> filters);

	}

	/**
	 * A {@link FilterChainDecorator} that uses the {@link VirtualFilterChain}
	 *
	 * @author Josh Cummings
	 * @since 6.0
	 */
	// 主要职责是利用经典的 VirtualFilterChain 机制，将安全过滤器挂载到原始的请求处理链上。
	// 实现“虚拟”链逻辑：在 Servlet 规范中，FilterChain 通常由容器（如 Tomcat）维护。为了在不改变容器配置的情况下插入几十个安全过滤器，Spring Security 创建了一个“虚拟”的内部链。
	// 桥接作用：它充当了工厂的角色。它接收原始的 Servlet FilterChain，并根据传入的 filters 列表，生产出一个 VirtualFilterChain 实例。
	// 默认降级方案：当没有任何安全过滤器（filters 为空）时，它非常聪明地选择“不作为”，直接返回原始链，从而保证了性能。
	public static final class VirtualFilterChainDecorator implements FilterChainDecorator {

		/**
		 * {@inheritDoc}
		 */
		@Override
		public FilterChain decorate(FilterChain original) {
			return original;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public FilterChain decorate(FilterChain original, List<Filter> filters) {
			return new VirtualFilterChain(original, filters);
		}

	}

	private static final class FirewallFilter implements Filter {

		private final HttpFirewall firewall;

		private FirewallFilter(HttpFirewall firewall) {
			this.firewall = firewall;
		}

		@Override
		public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
				throws IOException, ServletException {
			HttpServletRequest request = (HttpServletRequest) servletRequest;
			HttpServletResponse response = (HttpServletResponse) servletResponse;
			filterChain.doFilter(this.firewall.getFirewalledRequest(request),
					this.firewall.getFirewalledResponse(response));
		}

	}

}
