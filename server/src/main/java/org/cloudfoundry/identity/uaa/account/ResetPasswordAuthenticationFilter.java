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

import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ResetPasswordAuthenticationFilter extends OncePerRequestFilter {
    private final ResetPasswordService service;
    private final AuthenticationSuccessHandler handler;
    private final AuthenticationEntryPoint entryPoint;

    public ResetPasswordAuthenticationFilter(ResetPasswordService service, AuthenticationSuccessHandler handler, AuthenticationEntryPoint entryPoint) {
        this.service = service;
        this.handler = handler;
        this.entryPoint = entryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String email = request.getParameter("email");
        String code = request.getParameter("code");
        String password = request.getParameter("password");
        String passwordConfirmation = request.getParameter("password_confirmation");

        PasswordConfirmationValidation validation = new PasswordConfirmationValidation(password, passwordConfirmation);
        if (validation.valid()) {
            ResetPasswordService.ResetPasswordResponse resetPasswordResponse = service.resetPassword(code, password);
            ScimUser user = resetPasswordResponse.getUser();
            UaaPrincipal uaaPrincipal = new UaaPrincipal(user.getId(), user.getUserName(), user.getPrimaryEmail(), OriginKeys.UAA, null, IdentityZoneHolder.get().getId());
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
            SecurityContextHolder.getContext().setAuthentication(token);
            handler.onAuthenticationSuccess(request, response, token);
            return;
        } else{
            request.setAttribute("message_code", validation.getMessageCode());
            request.setAttribute("email", email);
            entryPoint.commence(request, response, new AccountNotVerifiedException("Password not validated"));
        }



    }
}
