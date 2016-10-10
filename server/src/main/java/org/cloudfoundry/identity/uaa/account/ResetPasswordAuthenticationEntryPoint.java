/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation.PasswordConfirmationException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class ResetPasswordAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        Throwable cause = authException.getCause();
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        if (cause instanceof PasswordConfirmationException) {
            PasswordConfirmationException passwordConfirmationException = (PasswordConfirmationException) cause;
            request.setAttribute("code", request.getParameter("code"));
            request.setAttribute("message_code", passwordConfirmationException.getMessageCode());
            request.setAttribute("email", passwordConfirmationException.getEmail());
            request.getRequestDispatcher("/reset_password").forward(request, response);
            return;
        } else {
            if (cause instanceof InvalidPasswordException) {
                InvalidPasswordException exception = (InvalidPasswordException)cause;
                request.setAttribute("message", exception.getMessagesAsOneString());
            } else {
                request.setAttribute("message_code", "bad_code");
            }
            request.getRequestDispatcher("/forgot_password").forward(request, response);
        }
    }
}
