/*
 *    Copyright 2019 Google LLC
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package com.google.auth.oauth2;

import com.google.api.client.util.Key;

@SuppressWarnings("javadoc")
public final class CredentialsJson extends com.google.api.client.json.GenericJson {

    @Key("type")
    private String type;
    public String getType() {
        return type;
    }

    @Key("client_id")
    private String clientId;
    public String getClientId() {
        return clientId;
    }

    @Key("client_secret")
    private String clientSecret;
    public String getClientSecret() {
        return clientSecret;
    }

    @Key("refresh_token")
    private String refreshToken;
    public String getRefreshToken() {
        return refreshToken;
    }

    @Key("project_id")
    private java.lang.String projectId;
    public java.lang.String getProjectId() {
        return projectId;
    }

    @Key("private_key_id")
    private java.lang.String privateKeyId;
    public java.lang.String getPrivateKeyId() {
        return privateKeyId;
    }

    @Key("private_key")
    private java.lang.String privateKeyPem;
    public java.lang.String getPrivateKeyPem() {
        return privateKeyPem;
    }

    @Key("client_email")
    private java.lang.String clientEmail;
    public java.lang.String getClientEmail() {
        return clientEmail;
    }

    @Key("auth_uri")
    private java.lang.String authUri;
    public java.lang.String getAuthUri() {
        return authUri;
    }

    @Key("token_uri")
    private java.lang.String tokenUri;
    public java.lang.String getTokenUri() {
        return tokenUri;
    }

    @Key("auth_provider_x509_cert_url")
    private java.lang.String authProviderX509CertUrl;
    public java.lang.String getAuthProviderX509CertUrl() {
        return authProviderX509CertUrl;
    }

    @Key("client_x509_cert_url")
    private java.lang.String clientX509CertUrl;
    public java.lang.String getClientX509CertUrl() {
        return clientX509CertUrl;
    }

}
