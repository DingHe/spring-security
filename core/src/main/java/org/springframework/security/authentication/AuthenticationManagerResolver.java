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

package org.springframework.security.authentication;

/**
 * An interface for resolving an {@link AuthenticationManager} based on the provided
 * context
 *
 * @author Josh Cummings
 * @since 5.2
 */
// 在标准的 Spring Security 配置中，通常只有一个全局的 AuthenticationManager。但在复杂的企业级场景下，这种“一刀切”的方式往往不够用。
// AuthenticationManagerResolver 的核心作用是：根据请求的上下文（Context），动态地决定使用哪一个认证管理器（AuthenticationManager）。
public interface AuthenticationManagerResolver<C> {

	/**
	 * Resolve an {@link AuthenticationManager} from a provided context
	 * @param context
	 * @return the {@link AuthenticationManager} to use
	 */
	AuthenticationManager resolve(C context);

}
