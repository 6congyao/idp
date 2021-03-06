/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.services.resources;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.OAuthErrorException;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.AuthorizationService;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.clientregistration.ClientRegistrationService;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.account.AccountLoader;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.services.util.ResolveRelative;
import org.keycloak.wellknown.WellKnownProvider;
import org.keycloak.representations.idm.GroupRepresentation;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Path("/realms")
public class RealmsResource {
    protected static final Logger logger = Logger.getLogger(RealmsResource.class);

    @Context
    protected KeycloakSession session;

    @Context
    protected ClientConnection clientConnection;

    @Context
    private HttpRequest request;

    public static UriBuilder realmBaseUrl(UriInfo uriInfo) {
        UriBuilder baseUriBuilder = uriInfo.getBaseUriBuilder();
        return realmBaseUrl(baseUriBuilder);
    }

    public static UriBuilder realmBaseUrl(UriBuilder baseUriBuilder) {
        return baseUriBuilder.path(RealmsResource.class).path(RealmsResource.class, "getRealmResource");
    }

    public static UriBuilder accountUrl(UriBuilder base) {
        return base.path(RealmsResource.class).path(RealmsResource.class, "getAccountService");
    }

    public static UriBuilder protocolUrl(UriInfo uriInfo) {
        return uriInfo.getBaseUriBuilder().path(RealmsResource.class).path(RealmsResource.class, "getProtocol");
    }

    public static UriBuilder protocolUrl(UriBuilder builder) {
        return builder.path(RealmsResource.class).path(RealmsResource.class, "getProtocol");
    }

    public static UriBuilder clientRegistrationUrl(UriInfo uriInfo) {
        return uriInfo.getBaseUriBuilder().path(RealmsResource.class).path(RealmsResource.class, "getClientsService");
    }

    public static UriBuilder brokerUrl(UriInfo uriInfo) {
        return uriInfo.getBaseUriBuilder().path(RealmsResource.class).path(RealmsResource.class, "getBrokerService");
    }

    public static UriBuilder wellKnownProviderUrl(UriBuilder builder) {
        return builder.path(RealmsResource.class).path(RealmsResource.class, "getWellKnown");
    }

    @Path("{realm}/protocol/{protocol}")
    public Object getProtocol(final @PathParam("realm") String name,
                              final @PathParam("protocol") String protocol) {
        RealmModel realm = init(name);

        LoginProtocolFactory factory = (LoginProtocolFactory)session.getKeycloakSessionFactory().getProviderFactory(LoginProtocol.class, protocol);
        if(factory == null){
            logger.debugf("protocol %s not found", protocol);
            throw new NotFoundException("Protocol not found");
        }

        EventBuilder event = new EventBuilder(realm, session, clientConnection);

        Object endpoint = factory.createProtocolEndpoint(realm, event);

        ResteasyProviderFactory.getInstance().injectProperties(endpoint);
        return endpoint;
    }

    /**
     * Returns a temporary redirect to the client url configured for the given {@code clientId} in the given {@code realmName}.
     * <p>
     * This allows a client to refer to other clients just by their client id in URLs, will then redirect users to the actual client url.
     * The client url is derived according to the rules of the base url in the client configuration.
     * </p>
     *
     * @param realmName
     * @param clientId
     * @return
     * @since 2.0
     */
    @GET
    @Path("{realm}/clients/{client_id}/redirect")
    public Response getRedirect(final @PathParam("realm") String realmName, final @PathParam("client_id") String clientId) {

        RealmModel realm = init(realmName);

        if (realm == null) {
            return null;
        }

        ClientModel client = realm.getClientByClientId(clientId);

        if (client == null) {
            return null;
        }

        if (client.getRootUrl() == null && client.getBaseUrl() == null) {
            return null;
        }


        URI targetUri;
        if (client.getRootUrl() != null && (client.getBaseUrl() == null || client.getBaseUrl().isEmpty())) {
            targetUri = KeycloakUriBuilder.fromUri(client.getRootUrl()).build();
        } else {
            targetUri = KeycloakUriBuilder.fromUri(ResolveRelative.resolveRelativeUri(session, client.getRootUrl(), client.getBaseUrl())).build();
        }

        return Response.seeOther(targetUri).build();
    }

    @Path("{realm}/login-actions")
    public LoginActionsService getLoginActionsService(final @PathParam("realm") String name) {
        RealmModel realm = init(name);
        EventBuilder event = new EventBuilder(realm, session, clientConnection);
        LoginActionsService service = new LoginActionsService(realm, event);
        ResteasyProviderFactory.getInstance().injectProperties(service);
        return service;
    }

    @Path("{realm}/clients-registrations")
    public ClientRegistrationService getClientsService(final @PathParam("realm") String name) {
        RealmModel realm = init(name);
        EventBuilder event = new EventBuilder(realm, session, clientConnection);
        ClientRegistrationService service = new ClientRegistrationService(event);
        ResteasyProviderFactory.getInstance().injectProperties(service);
        return service;
    }

    @Path("{realm}/clients-managements")
    public ClientsManagementService getClientsManagementService(final @PathParam("realm") String name) {
        RealmModel realm = init(name);
        EventBuilder event = new EventBuilder(realm, session, clientConnection);
        ClientsManagementService service = new ClientsManagementService(realm, event);
        ResteasyProviderFactory.getInstance().injectProperties(service);
        return service;
    }

    private RealmModel init(String realmName) {
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.getRealmByName(realmName);
        if (realm == null) {
            throw new NotFoundException("Realm does not exist");
        }
        session.getContext().setRealm(realm);
        return realm;
    }

    @Path("{realm}/account")
    public Object getAccountService(final @PathParam("realm") String name) {
        RealmModel realm = init(name);
        EventBuilder event = new EventBuilder(realm, session, clientConnection);
        AccountLoader accountLoader = new AccountLoader(session, event);
        ResteasyProviderFactory.getInstance().injectProperties(accountLoader);
        return accountLoader;
    }

    @Path("{realm}")
    public PublicRealmResource getRealmResource(final @PathParam("realm") String name) {
        RealmModel realm = init(name);
        PublicRealmResource realmResource = new PublicRealmResource(realm);
        ResteasyProviderFactory.getInstance().injectProperties(realmResource);
        return realmResource;
    }

    @Path("{realm}/broker")
    public IdentityBrokerService getBrokerService(final @PathParam("realm") String name) {
        RealmModel realm = init(name);

        IdentityBrokerService brokerService = new IdentityBrokerService(realm);
        ResteasyProviderFactory.getInstance().injectProperties(brokerService);

        brokerService.init();

        return brokerService;
    }

    @OPTIONS
    @Path("{realm}/.well-known/{provider}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getVersionPreflight(final @PathParam("realm") String name,
                                        final @PathParam("provider") String providerName) {
        return Cors.add(request, Response.ok()).allowedMethods("GET").preflight().auth().build();
    }

    @GET
    @Path("{realm}/.well-known/{provider}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getWellKnown(final @PathParam("realm") String name,
                                 final @PathParam("provider") String providerName) {
        RealmModel realm = init(name);
        checkSsl(realm);

        WellKnownProvider wellKnown = session.getProvider(WellKnownProvider.class, providerName);

        if (wellKnown != null) {
            ResponseBuilder responseBuilder = Response.ok(wellKnown.getConfig()).cacheControl(CacheControlUtil.noCache());
            return Cors.add(request, responseBuilder).allowedOrigins("*").auth().build();
        }

        throw new NotFoundException();
    }

    @Path("{realm}/authz")
    public Object getAuthorizationService(@PathParam("realm") String name) {
        init(name);
        AuthorizationProvider authorization = this.session.getProvider(AuthorizationProvider.class);
        AuthorizationService service = new AuthorizationService(authorization);

        ResteasyProviderFactory.getInstance().injectProperties(service);

        return service;
    }

    /**
     * A JAX-RS sub-resource locator that uses the {@link org.keycloak.services.resource.RealmResourceSPI} to resolve sub-resources instances given an <code>unknownPath</code>.
     *
     * @param extension a path that could be to a REST extension
     * @return a JAX-RS sub-resource instance for the REST extension if found. Otherwise null is returned.
     */
    @Path("{realm}/{extension}")
    public Object resolveRealmExtension(@PathParam("realm") String realmName, @PathParam("extension") String extension) {
        RealmResourceProvider provider = session.getProvider(RealmResourceProvider.class, extension);
        if (provider != null) {
            init(realmName);
            Object resource = provider.getResource();
            if (resource != null) {
                return resource;
            }
        }

        throw new NotFoundException();
    }

    /**
     * Get openids
     *
     * Returns a set of openids, filtered according to query parameters
     *
     * @param groups A String contained in groups
     * @param roles A String contained in roles
     * @return a non-null map of openids
     */
    @GET
    @Path("{realm}/openid")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, List<String>> getOpenID(final @PathParam("realm") String name,
                                @QueryParam("groups") String groups,
                                @QueryParam("roles") @DefaultValue("hycr_operator,hycr_programmer") String roles) {
        RealmModel realm = init(name);
        checkSsl(realm);

        String[] gSet = groups.split(",");
        String[] rSet = roles.split(",");

        return realm.getTopLevelGroupsStream().filter(g -> {
            for (String gStr : gSet) {
                if (g.getName().contains(gStr.trim())) {
                    return true;
                }
            }
            return false;
        }).flatMap(g -> 
            session.users().getGroupMembersStream(realm, g)
        ).filter(u -> !ObjectUtil.isBlank(u.getEmail())
        ).filter(u -> {
            for (String rStr : rSet) {
                if (u.getRealmRoleMappingsStream().anyMatch(r -> r.getName().equalsIgnoreCase(rStr.trim()))) {
                    return true;
                }
            }
            return false;
        }).map(u -> ModelToRepresentation.toRepresentation(session, realm, u)
        ).collect(Collectors.toMap(e -> String.valueOf(e.getGroups().get(0)).split("\\|")[0], e -> {
            ArrayList<String> list = new ArrayList<>();
            List<String> oids = e.getAttributes().get("openid");
            if (oids != null) {
                list.add(oids.get(0));
            }
            return list;
        }, (oldList, newList) -> {
            oldList.addAll(newList);
            return oldList;
        }));
    }

    @GET
    @Path("{realm}/groups")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Stream<GroupRepresentation> getGroups(final @PathParam("realm") String name) {
        RealmModel realm = init(name);
        checkSsl(realm);

        return ModelToRepresentation.toGroupHierarchy(session, realm, false);
    }

    @GET
    @Path("{realm}/groups/ex")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Stream<GroupRepresentation> getExGroups(final @PathParam("realm") String name) {
        RealmModel realm = init(name);
        checkSsl(realm);

        return ModelToRepresentation.toExGroupHierarchy(session, realm, false);
    }

    private void checkSsl(RealmModel realm) {
        if (!session.getContext().getUri().getBaseUri().getScheme().equals("https")
                && realm.getSslRequired().isRequired(clientConnection)) {
            Cors cors = Cors.add(request).auth().allowedMethods(request.getHttpMethod()).auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_REQUEST, "HTTPS required",
                    Response.Status.FORBIDDEN);
        }
    }
}
