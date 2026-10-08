/**
 * Copyright (c) 2002-2017 "Neo Technology,"
 * Network Engine for Objects in Lund AB [http://neotechnology.com]
 *
 * This file is part of Neo4j.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.neo4j.example.auth.plugin.entitlements;

import com.google.gson.Gson;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthProviderOperations;
import com.neo4j.server.security.enterprise.auth.plugin.spi.AuthorizationInfo;
import com.neo4j.server.security.enterprise.auth.plugin.spi.AuthorizationPlugin;
import java.io.BufferedReader;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Properties;

// TODO: trim down this AI-generated docstring
/**
 * This example shows how a pure {@link AuthorizationPlugin} — one that never authenticates — can enrich
 * the roles and user tags of natively authenticated users by looking them up in an internal entitlements
 * service over REST.
 *
 * The plugin is configured as an authorization provider only, alongside the built-in `native` provider:
 *
 * <pre>
 * dbms.security.authorization_providers=native,plugin-user-entitlements
 * dbms.security.abac.authorization_providers=plugin-user-entitlements
 * </pre>
 *
 * In policy-engine terms (NIST SP 800-162): Neo4j is both the policy enforcement point and the policy
 * decision point — its own auth rules and privilege rules do the deciding. The entitlements service is a
 * policy information point: the retrieval source of the attributes (the user tags) that those decisions
 * consume. There is no standardized protocol for pulling attributes from a policy information point, so a
 * bespoke internal REST service is the common modern pattern.
 *
 * Tags are flat opaque strings, only ever used in membership checks such as
 * `CREATE AUTH RULE pii READERS SET CONDITION 'pii-access' IN abac.plugin.user_tags()`.
 *
 * The service is expected to answer `GET {service-uri}/users/{username}/entitlements` with
 * `{"groups": ["..."], "tags": ["..."]}`, where groups become Neo4j roles one-to-one and tags are passed
 * through unchanged. Replace the fetch in {@link #getUserEntitlements(String)} with your own source of
 * entitlements (LDAP, JDBC against control tables, gRPC, Microsoft Graph, ...) — that is the one part of
 * this example that is bespoke by nature.
 */
public class UserEntitlementsAuthorizationPlugin extends AuthorizationPlugin.Adapter {
    public static final String PLUGIN_NAME = "user-entitlements";
    public static final String SERVICE_URI_SETTING = "entitlements_service_uri";
    public static final String SERVICE_TOKEN_SETTING = "entitlements_service_token";

    private static final String SERVICE_TOKEN_HEADER = "Authorization";
    private static final String ENTITLEMENTS_PATH = "/users/%s/entitlements";

    private final Gson gson = new Gson();

    private AuthProviderOperations api;
    private HttpClient httpClient;
    private String serviceUri;
    private String serviceToken;

    @Override
    public String name() {
        return PLUGIN_NAME;
    }

    @Override
    public void initialize(AuthProviderOperations authProviderOperations) {
        api = authProviderOperations;

        Properties properties = new Properties();
        try (BufferedReader reader = Files.newBufferedReader(configPath())) {
            properties.load(reader);
        } catch (IOException e) {
            throw new IllegalStateException("Failed loading properties: " + e.getMessage(), e);
        }

        serviceUri = properties.getProperty(SERVICE_URI_SETTING);
        if (serviceUri == null) {
            throw new IllegalStateException("Missing entitlements service setting '" + SERVICE_URI_SETTING + "'.");
        }
        serviceToken = properties.getProperty(SERVICE_TOKEN_SETTING);
        if (serviceToken == null) {
            throw new IllegalStateException("Missing entitlements service setting '" + SERVICE_TOKEN_SETTING + "'.");
        }

        // One client for the lifetime of the plugin: it owns a connection pool, so reusing it lets
        // consecutive lookups share pooled connections instead of paying a fresh one every time.
        httpClient = HttpClient.newHttpClient();

        api.log().info("initialized!");
    }

    @Override
    public AuthorizationInfo authorize(Collection<PrincipalAndProvider> principals) {
        // TODO: I thought this felt janky, but turns out this is how Shiro's default .getPrimaryPrincipal() is implemented. Nevertheless, I think it the assumption that first principal-realm pair is the primary principal should be clearer?
        // With the built-in `native` provider doing the authenticating, the collection holds the single
        // native principal; its `toString()` is the username.
        String username = principals.iterator().next().principal().toString();

        try {
            UserEntitlements entitlements = getUserEntitlements(username);
            // Groups become roles one-to-one. Real deployments translate the organisation's group names
            // into Neo4j role names instead — some providers, like Entra ID, put opaque group GUIDs here,
            // which cannot be passed through directly.
            return AuthorizationInfo.of(entitlements.groups(), entitlements.tags());
        } catch (Exception e) {
            // Fail closed: no entitlements, no roles, no tags.
            api.log().warn("Failed getting entitlements for user '" + username + "': " + e.getMessage());
            return null;
        }
    }

    private Path configPath() {
        return api.neo4jHome().resolve("conf/entitlements.conf");
    }

    private UserEntitlements getUserEntitlements(String username) throws IOException, InterruptedException {
        // The username is an untrusted path segment; encode it so it cannot carry '/' or '..' into the URI.
        String uri = serviceUri + ENTITLEMENTS_PATH.formatted(URLEncoder.encode(username, StandardCharsets.UTF_8));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .header(SERVICE_TOKEN_HEADER, "Bearer " + serviceToken)
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Entitlements service returned status " + response.statusCode());
        }

        return gson.fromJson(response.body(), UserEntitlements.class);
    }
}
