/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static junit.framework.TestCase.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ResetPasswordAuthenticationFilterTest {

    private String code;
    private String password;
    private String passwordConfirmation;
    private MockHttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;
    private ResetPasswordService service;
    private ScimUser user;
    private ResetPasswordService.ResetPasswordResponse resetPasswordResponse;
    private ResetPasswordAuthenticationFilter filter;
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    @Before
    @After
    public void clear() {
        SecurityContextHolder.clearContext();
    }

    @Before
    public void setup() throws Exception {
        code = "12345";
        password = "test";
        passwordConfirmation = "test";

        request = new MockHttpServletRequest("POST", "/reset_password.do");
        request.setParameter("code", code);
        request.setParameter("password", password);
        request.setParameter("password_confirmation", passwordConfirmation);

        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);

        service = mock(ResetPasswordService.class);
        user = new ScimUser("id", "username", "first name", "last name");
        resetPasswordResponse = new ResetPasswordService.ResetPasswordResponse(user, "/", null);
        when(service.resetPassword(eq(code), eq(password))).thenReturn(resetPasswordResponse);
        authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
        filter = new ResetPasswordAuthenticationFilter(service, authenticationSuccessHandler);
    }

    @Test
    public void test_happy_day_password_reset() throws Exception {
        filter.doFilterInternal(request, response, chain);
        //do our assertion
        verify(service, times(1)).resetPassword(eq(code), eq(password));
        verify(authenticationSuccessHandler, times(1)).onAuthenticationSuccess(same(request), same(response), any(Authentication.class));
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        verify(chain, times(0)).doFilter(anyObject(), anyObject());
    }


    @Test
    public void invalid_password_confirmation() throws Exception {
        request.setParameter("password_confirmation", "invalid");
        filter.doFilterInternal(request, response, chain);
        //do our assertion
        verify(authenticationSuccessHandler, times(0)).onAuthenticationSuccess(same(request), same(response), any(Authentication.class));
        verify(service, times(0)).resetPassword(eq(code), eq(password));
        verify(response, times(0)).sendRedirect("/reset_password");
        verify(request, times(1)).getRequestDispatcher(eq("/reset_password"));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }



}