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

package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static org.cloudfoundry.identity.uaa.zone.SSLConfiguration.VerificationType.DEFUALT;
import static org.cloudfoundry.identity.uaa.zone.SSLConfiguration.VerificationType.STRICT;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SSLConfiguration {
    public enum VerificationType {
        DEFUALT,
        LENIENT,
        STRICT
    }

    private VerificationType verificationType = STRICT;
    private String[] enabledCiphers = null;
    private Boolean verifyHostname = null;
    private Boolean checkExpiry = TRUE;
    private String[] trustedCertificates = null;

    public SSLConfiguration() {
        this.verificationType = DEFUALT;
    }

    public SSLConfiguration(VerificationType verificationType) {
        this.verificationType = verificationType;
        switch (verificationType) {
            case STRICT:
                verifyHostname = TRUE;
                checkExpiry = TRUE;
                verifyHostname = TRUE;
                break;
            case LENIENT:
                verifyHostname = FALSE;
                checkExpiry = FALSE;
                break;

        }
    }

    public VerificationType getVerificationType() {
        return verificationType;
    }

    public void setVerificationType(VerificationType verificationType) {
        this.verificationType = verificationType;
    }

    public String[] getEnabledCiphers() {
        return enabledCiphers;
    }

    public void setEnabledCiphers(String[] enabledCiphers) {
        this.enabledCiphers = enabledCiphers;
    }

    public Boolean getVerifyHostname() {
        return verifyHostname;
    }

    public void setVerifyHostname(Boolean verifyHostname) {
        this.verifyHostname = verifyHostname;
    }

    public Boolean getCheckExpiry() {
        return checkExpiry;
    }

    public void setCheckExpiry(Boolean checkExpiry) {
        this.checkExpiry = checkExpiry;
    }

    public String[] getTrustedCertificates() {
        return trustedCertificates;
    }

    public void setTrustedCertificates(String[] trustedCertificates) {
        this.trustedCertificates = trustedCertificates;
    }
}
