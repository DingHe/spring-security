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

package org.springframework.security.authentication.dao;

import java.util.function.Supplier;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;
import org.springframework.util.function.SingletonSupplier;

/**
 * An {@link AuthenticationProvider} implementation that retrieves user details from a
 * {@link UserDetailsService}.
 *
 * @author Ben Alex
 * @author Rob Winch
 */
// DaoAuthenticationProvider 是 Spring Security 中最常用、最经典的身份认证执行者。
// 它是 AbstractUserDetailsAuthenticationProvider 的具体实现，专门负责从数据库（或其他持久化存储）中获取用户信息并验证密码。
// 它的核心作用是**“通过数据访问对象（DAO）进行认证”**。
// 它将认证逻辑与具体的存储方式解耦：
// 数据检索：它不直接操作数据库，而是委托给 UserDetailsService 来查找用户。
// 密码校验：它不直接比对字符串，而是委托给 PasswordEncoder 来处理加密后的密码比对。
// 安全性增强：它内置了防止**计时攻击（Timing Attack）**的机制，并支持在认证成功后自动升级密码加密强度。
public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

	/**
	 * The plaintext password used to perform
	 * {@link PasswordEncoder#matches(CharSequence, String)} on when the user is not found
	 * to avoid SEC-2056.
	 */
	// 静态常量。当用户不存在时，用于参与伪装比对的明文密码。
	private static final String USER_NOT_FOUND_PASSWORD = "userNotFoundPassword";
	// 密码解析器。默认使用委派密码编码器。负责验证用户输入的密码与数据库存储的 Hash 是否匹配。
	private Supplier<PasswordEncoder> passwordEncoder = SingletonSupplier
		.of(PasswordEncoderFactories::createDelegatingPasswordEncoder);

	/**
	 * The password used to perform {@link PasswordEncoder#matches(CharSequence, String)}
	 * on when the user is not found to avoid SEC-2056. This is necessary, because some
	 * {@link PasswordEncoder} implementations will short circuit if the password is not
	 * in a valid format.
	 */
	// 防止计时攻击的关键。存储一个预先加密好的“空用户密码”。
	private volatile String userNotFoundEncodedPassword;
	// 用户服务。核心依赖，用于根据用户名加载 UserDetails 对象。
	private UserDetailsService userDetailsService;
	// 密码自动升级服务。可选。如果设置了，当密码加密算法过时，它会自动保存升级后的新 Hash。
	private UserDetailsPasswordService userDetailsPasswordService;
	// 被泄露密码检查器。Spring Security 6.3 引入，用于检查用户密码是否出现在已知的泄露数据库中。
	private CompromisedPasswordChecker compromisedPasswordChecker;

	/**
	 * @deprecated Please provide the {@link UserDetailsService} in the constructor
	 */
	@Deprecated
	public DaoAuthenticationProvider() {
	}

	public DaoAuthenticationProvider(UserDetailsService userDetailsService) {
		setUserDetailsService(userDetailsService);
	}

	/**
	 * Creates a new instance using the provided {@link PasswordEncoder}
	 * @param passwordEncoder the {@link PasswordEncoder} to use. Cannot be null.
	 * @since 6.0.3
	 * @deprecated Please provide the {@link UserDetailsService} in the constructor
	 * followed by {@link #setPasswordEncoder(PasswordEncoder)} instead
	 */
	@Deprecated
	public DaoAuthenticationProvider(PasswordEncoder passwordEncoder) {
		setPasswordEncoder(passwordEncoder);
	}

	@Override
	@SuppressWarnings("deprecation")
	protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
		if (authentication.getCredentials() == null) {
			this.logger.debug("Failed to authenticate since no credentials provided");
			throw new BadCredentialsException(this.messages
				.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}
		String presentedPassword = authentication.getCredentials().toString();
		if (!this.passwordEncoder.get().matches(presentedPassword, userDetails.getPassword())) {
			this.logger.debug("Failed to authenticate since password does not match stored value");
			throw new BadCredentialsException(this.messages
				.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}
	}

	@Override
	protected void doAfterPropertiesSet() {
		Assert.notNull(this.userDetailsService, "A UserDetailsService must be set");
	}

	@Override
	protected final UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		prepareTimingAttackProtection();
		try {
			UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
			if (loadedUser == null) {
				throw new InternalAuthenticationServiceException(
						"UserDetailsService returned null, which is an interface contract violation");
			}
			return loadedUser;
		}
		catch (UsernameNotFoundException ex) {
			mitigateAgainstTimingAttack(authentication);
			throw ex;
		}
		catch (InternalAuthenticationServiceException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
		}
	}

	@Override
	protected Authentication createSuccessAuthentication(Object principal, Authentication authentication,
			UserDetails user) {
		String presentedPassword = authentication.getCredentials().toString();
		boolean isPasswordCompromised = this.compromisedPasswordChecker != null
				&& this.compromisedPasswordChecker.check(presentedPassword).isCompromised();
		if (isPasswordCompromised) {
			throw new CompromisedPasswordException("The provided password is compromised, please change your password");
		}
		boolean upgradeEncoding = this.userDetailsPasswordService != null
				&& this.passwordEncoder.get().upgradeEncoding(user.getPassword());
		if (upgradeEncoding) {
			String newPassword = this.passwordEncoder.get().encode(presentedPassword);
			user = this.userDetailsPasswordService.updatePassword(user, newPassword);
		}
		return super.createSuccessAuthentication(principal, authentication, user);
	}

	private void prepareTimingAttackProtection() {
		if (this.userNotFoundEncodedPassword == null) {
			this.userNotFoundEncodedPassword = this.passwordEncoder.get().encode(USER_NOT_FOUND_PASSWORD);
		}
	}

	private void mitigateAgainstTimingAttack(UsernamePasswordAuthenticationToken authentication) {
		if (authentication.getCredentials() != null) {
			String presentedPassword = authentication.getCredentials().toString();
			this.passwordEncoder.get().matches(presentedPassword, this.userNotFoundEncodedPassword);
		}
	}

	/**
	 * Sets the PasswordEncoder instance to be used to encode and validate passwords. If
	 * not set, the password will be compared using
	 * {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}
	 * @param passwordEncoder must be an instance of one of the {@code PasswordEncoder}
	 * types.
	 */
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
		this.passwordEncoder = () -> passwordEncoder;
		this.userNotFoundEncodedPassword = null;
	}

	protected PasswordEncoder getPasswordEncoder() {
		return this.passwordEncoder.get();
	}

	/**
	 * @param userDetailsService
	 * @deprecated Please provide the {@link UserDetailsService} in the constructor
	 */
	@Deprecated
	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	protected UserDetailsService getUserDetailsService() {
		return this.userDetailsService;
	}

	public void setUserDetailsPasswordService(UserDetailsPasswordService userDetailsPasswordService) {
		this.userDetailsPasswordService = userDetailsPasswordService;
	}

	/**
	 * Sets the {@link CompromisedPasswordChecker} to be used before creating a successful
	 * authentication. Defaults to {@code null}.
	 * @param compromisedPasswordChecker the {@link CompromisedPasswordChecker} to use
	 * @since 6.3
	 */
	public void setCompromisedPasswordChecker(CompromisedPasswordChecker compromisedPasswordChecker) {
		this.compromisedPasswordChecker = compromisedPasswordChecker;
	}

}
