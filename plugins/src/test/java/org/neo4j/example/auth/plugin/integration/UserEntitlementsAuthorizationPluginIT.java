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
package org.neo4j.example.auth.plugin.integration;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.neo4j.configuration.connectors.BoltConnector.DEFAULT_PORT;

import com.google.gson.Gson;
import com.neo4j.configuration.SecuritySettings;
import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.io.FileWriter;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.neo4j.configuration.GraphDatabaseInternalSettings;
import org.neo4j.configuration.GraphDatabaseSettings;
import org.neo4j.configuration.connectors.BoltConnector;
import org.neo4j.configuration.helpers.SocketAddress;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Config;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.driver.Logging;
import org.neo4j.driver.Session;
import org.neo4j.driver.SessionConfig;
import org.neo4j.example.auth.plugin.entitlements.UserEntitlements;
import org.neo4j.example.auth.plugin.entitlements.UserEntitlementsAuthorizationPlugin;
import org.neo4j.harness.Neo4j;
import org.neo4j.io.layout.Neo4jLayout;
import org.neo4j.test.extension.Inject;
import org.neo4j.test.extension.testdirectory.TestDirectoryExtension;
import org.neo4j.test.utils.TestDirectory;

/**
 * Starts Neo4j with native authentication and the {@link UserEntitlementsAuthorizationPlugin} as an
 * additional authorization provider, alongside a stub of the internal entitlements service that the
 * plugin fetches from.
 */
@TestDirectoryExtension
public class UserEntitlementsAuthorizationPluginIT {
    private static final String PASSWORD = "abc12345";
    private static final String ADMIN_PASSWORD = "xyz6789abcd";
    private static final String SERVICE_TOKEN = "test-service-token";

    private static final String TAG_USER = "tank";
    private static final String GROUP_USER = "neo";
    private static final String UNKNOWN_USER = "trinity";

    private static final String PII_TAG = "pii-access";
    private static final String PII_ROLE = "piiRole";
    private static final String GROUP_ROLE = "entitlementsRole";

    private static final Config config =
            Config.builder().withLogging(Logging.none()).withoutEncryption().build();

    // The entitlements each user gets from the stub service.
    private static final Map<String, UserEntitlements> ENTITLEMENTS = Map.of(
            TAG_USER, new UserEntitlements(List.of(), List.of(PII_TAG)),
            GROUP_USER, new UserEntitlements(List.of(GROUP_ROLE), List.of()));

    @Inject
    private TestDirectory testDirectory;

    private HttpServer service;
    private Neo4j databases;
    private final Map<String, UserEntitlements> servedEntitlements = new ConcurrentHashMap<>();

    @BeforeEach
    public void setup() throws Exception {
        // The stub entitlements service: GET /users/{username}/entitlements -> the test data, 404 otherwise.
        service = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        servedEntitlements.putAll(ENTITLEMENTS);
        Gson gson = new Gson();
        service.createContext("/users", exchange -> {
            String username = exchange.getRequestURI()
                    .getPath()
                    .substring(
                            "/users/".length(),
                            exchange.getRequestURI().getPath().length() - "/entitlements".length());
            UserEntitlements entitlements = ("Bearer " + SERVICE_TOKEN)
                            .equals(exchange.getRequestHeaders().getFirst("Authorization"))
                    ? servedEntitlements.get(username)
                    : null;
            if (entitlements == null) {
                exchange.sendResponseHeaders(404, -1);
            } else {
                byte[] body = gson.toJson(entitlements).getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            }
            exchange.close();
        });
        service.start();

        PluginInProcessNeo4jBuilder builder = new PluginInProcessNeo4jBuilder(testDirectory.homePath());
        Neo4jLayout home = Neo4jLayout.of(builder.getRealServerPath());

        // Write out the plugin's config file, pointing it at the stub service
        File configDir = new File(home.homeDirectory().toFile(), "conf");
        configDir.mkdirs();
        try (FileWriter fileWriter = new FileWriter(new File(configDir, "entitlements.conf"))) {
            fileWriter.write(UserEntitlementsAuthorizationPlugin.SERVICE_URI_SETTING + "=http://localhost:"
                    + service.getAddress().getPort());
            fileWriter.write(System.lineSeparator());
            fileWriter.write(UserEntitlementsAuthorizationPlugin.SERVICE_TOKEN_SETTING + "=" + SERVICE_TOKEN);
        }

        String pluginProvider = "plugin-" + UserEntitlementsAuthorizationPlugin.PLUGIN_NAME;
        databases = builder.withConfig(GraphDatabaseSettings.auth_enabled, true)
                .withConfig(SecuritySettings.authentication_providers, List.of("native")) // just to be verbose, even though this is the default
                .withConfig(SecuritySettings.authorization_providers, List.of("native", pluginProvider)) // for simplicity do we want just plugin to be our authz provider?
                .withConfig(SecuritySettings.abac_authorization_providers, List.of(pluginProvider))
                .withConfig(GraphDatabaseInternalSettings.plugin_user_tags, true)
                .withConfig(BoltConnector.enabled, true)
                .withConfig(BoltConnector.listen_address, new SocketAddress("localhost", DEFAULT_PORT))
                .build();

        // The default admin password must be changed before the admin user can be used for anything else
        try (Driver driver = GraphDatabase.driver(databases.boltURI(), AuthTokens.basic("neo4j", "neo4j"), config);
                Session session = driver.session(SessionConfig.forDatabase("system"))) {
            session.run(
                            "ALTER CURRENT USER SET PASSWORD FROM $old TO $new",
                            Map.of("old", "neo4j", "new", ADMIN_PASSWORD))
                    .consume();
        }

        try (Driver driver =
                        GraphDatabase.driver(databases.boltURI(), AuthTokens.basic("neo4j", ADMIN_PASSWORD), config);
                Session session = driver.session(SessionConfig.forDatabase("system"))) {
            for (String user : List.of(TAG_USER, GROUP_USER, UNKNOWN_USER)) {
                session.run(
                                "CREATE USER $user SET PASSWORD $password CHANGE NOT REQUIRED",
                                Map.of("user", user, "password", PASSWORD))
                        .consume();
            }
            session.run("CREATE ROLE " + PII_ROLE).consume();
            session.run("CREATE ROLE " + GROUP_ROLE).consume();
            session.run("CYPHER 25 CREATE AUTH RULE " + PII_ROLE + "Rule SET CONDITION '" + PII_TAG
                            + "' IN abac.plugin.user_tags()")
                    .consume();
            session.run("CYPHER 25 GRANT ROLE " + PII_ROLE + " TO AUTH RULE " + PII_ROLE + "Rule")
                    .consume();
        }
    }

    @AfterEach
    public void tearDown() {
        databases.close();
        service.stop(0);
    }

    @Test
    public void userWithTagGetsRoleFromAuthRule() {
        // The tag user has the 'pii-access' tag, which the auth rule grants 'piiRole' on
        try (Driver driver = GraphDatabase.driver(databases.boltURI(), AuthTokens.basic(TAG_USER, PASSWORD), config);
                Session session = driver.session()) {
            assertThat(currentRoles(session), hasItem(PII_ROLE.toLowerCase()));
        }

        // The group user does not have the tag, so the auth rule grants nothing
        try (Driver driver = GraphDatabase.driver(databases.boltURI(), AuthTokens.basic(GROUP_USER, PASSWORD), config);
                Session session = driver.session()) {
            assertThat(currentRoles(session), not(hasItem(PII_ROLE.toLowerCase())));
        }
    }

    @Test
    public void userWithGroupGetsRoleOneToOne() {
        try (Driver driver = GraphDatabase.driver(databases.boltURI(), AuthTokens.basic(GROUP_USER, PASSWORD), config);
                Session session = driver.session()) {
            assertThat(currentRoles(session), hasItem(GROUP_ROLE.toLowerCase()));
        }
    }

    @Test
    public void userWithoutEntitlementsGetsNoRolesFromPlugin() {
        // The service does not know this user and answers 404, so the plugin contributes nothing
        try (Driver driver =
                        GraphDatabase.driver(databases.boltURI(), AuthTokens.basic(UNKNOWN_USER, PASSWORD), config);
                Session session = driver.session()) {
            assertThat(currentRoles(session), not(hasItem(PII_ROLE.toLowerCase())));
            assertThat(currentRoles(session), not(hasItem(GROUP_ROLE.toLowerCase())));
        }
    }

    @Test
    public void serviceDownMeansPluginFailsClosed() {
        service.stop(0);

        try (Driver driver = GraphDatabase.driver(databases.boltURI(), AuthTokens.basic(GROUP_USER, PASSWORD), config);
                Session session = driver.session()) {
            // No roles from the plugin, but the login still works
            assertThat(currentRoles(session), not(hasItem(GROUP_ROLE.toLowerCase())));
        }
    }

    private static List<String> currentRoles(Session session) {
        return session.run("CALL dbms.showCurrentUser() YIELD roles")
                .single()
                .get("roles")
                .asList(v -> v.asString().toLowerCase());
    }
}
