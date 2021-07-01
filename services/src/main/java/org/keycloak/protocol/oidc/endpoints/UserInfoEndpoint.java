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
package org.keycloak.protocol.oidc.endpoints;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenCategory;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.protocol.oidc.TokenManager.NotBeforeCheck;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.Urls;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.UserInfoRequestContext;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.UserSessionCrossDCManager;
import org.keycloak.services.resources.Cors;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.services.util.MtlsHoKTokenUtil;
import org.keycloak.services.validation.Validation;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.userprofile.utils.UserUpdateHelper;
import org.keycloak.userprofile.validation.AttributeValidationResult;
import org.keycloak.userprofile.validation.UserProfileValidationResult;
import org.keycloak.userprofile.validation.ValidationResult;
import org.keycloak.utils.MediaType;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.keycloak.userprofile.profile.UserProfileContextFactory.forUserResource;
/**
 * @author pedroigor
 */
public class UserInfoEndpoint {

    @Context
    private HttpRequest request;

    @Context
    private HttpResponse response;

    @Context
    private KeycloakSession session;

    @Context
    private ClientConnection clientConnection;

    private final org.keycloak.protocol.oidc.TokenManager tokenManager;
    private final AppAuthManager appAuthManager;
    private final RealmModel realm;

    public UserInfoEndpoint(org.keycloak.protocol.oidc.TokenManager tokenManager, RealmModel realm) {
        this.realm = realm;
        this.tokenManager = tokenManager;
        this.appAuthManager = new AppAuthManager();
    }

    @Path("/")
    @OPTIONS
    public Response issueUserInfoPreflight() {
        return Cors.add(this.request, Response.ok()).auth().preflight().build();
    }

    @Path("/")
    @GET
    @NoCache
    public Response issueUserInfoGet(@Context final HttpHeaders headers) {
        String accessToken = this.appAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);
        return issueUserInfo(accessToken);
    }

    @Path("/")
    @POST
    @NoCache
    public Response issueUserInfoPost() {
        // Try header first
        HttpHeaders headers = request.getHttpHeaders();
        String accessToken = this.appAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);

        // Fallback to form parameter
        if (accessToken == null) {
            accessToken = request.getDecodedFormParameters().getFirst("access_token");
        }

        return issueUserInfo(accessToken);
    }

    @Path("full")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public UserRepresentation issueUserAttrGet(@Context final HttpHeaders headers) {
        String tokenString = this.appAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);    
        UserModel user = findValidUser(tokenString);

        return ModelToRepresentation.toRepresentation(session, realm, user);
    }

    @Path("full")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @NoCache
    public Response issueUserAttrPut(@Context final HttpHeaders headers, final UserRepresentation rep) {
        String tokenString = this.appAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);    
        UserModel user = findValidUser(tokenString);

        try {
            if (rep.isEnabled() != null && rep.isEnabled()) {
                UserLoginFailureModel failureModel = session.sessions().getUserLoginFailure(realm, user.getId());
                if (failureModel != null) {
                    failureModel.clearFailures();
                }
            }

            Response response = validateUserProfile(user, rep, session);
            if (response != null) {
                return response;
            }
            updateUserFromRep(user, rep, session, true);
            updateUserRolesFromRep(user, rep, realm);
            RepresentationToModel.updateGroups(rep, realm, user);
            RepresentationToModel.createCredentials(rep, session, realm, user, true);
            // adminEvent.operation(OperationType.UPDATE).resourcePath(session.getContext().getUri()).representation(rep).success();

            if (session.getTransactionManager().isActive()) {
                session.getTransactionManager().commit();
            }
            return Response.noContent().build();
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("User exists with same username or email");
        } catch (ReadOnlyException re) {
            return ErrorResponse.exists("User is read only!");
        } catch (ModelException me) {
            return ErrorResponse.error("Could not update user!", Status.BAD_REQUEST);
        } catch (ForbiddenException fe) {
            throw fe;
        } catch (Exception me) { // JPA
            return ErrorResponse.error("Could not update user!", Status.BAD_REQUEST);
        }
    }

    /**
     * Set up a new password for the user.
     *
     * @param cred The representation must contain a rawPassword with the plain-text password
     */
    @Path("full/reset-password")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public void resetPassword(@Context final HttpHeaders headers, CredentialRepresentation cred) {
        String tokenString = this.appAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);    
        UserModel user = findValidUser(tokenString);

        if (cred == null || cred.getValue() == null) {
            throw new BadRequestException("No password provided");
        }
        if (Validation.isBlank(cred.getValue())) {
            throw new BadRequestException("Empty password not allowed");
        }
        if (!session.userCredentialManager().isValid(realm, user, UserCredentialModel.password(cred.getCredentialData(), false))) {
            throw new BadRequestException("Incorrect old password");
        }
        
        try {
            session.userCredentialManager().updateCredential(realm, user, UserCredentialModel.password(cred.getValue(), false));
        } catch (IllegalStateException ise) {
            throw new BadRequestException("Resetting to N old passwords is not allowed.");
        } catch (ReadOnlyException mre) {
            throw new BadRequestException("Can't reset password as account is read only");
        } catch (ModelException e) {
            throw new ErrorResponseException(e.getMessage(), e.getLocalizedMessage(), Status.BAD_REQUEST);
        }
        if (cred.isTemporary() != null && cred.isTemporary()) {
            user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        } else {
            // Remove a potentially existing UPDATE_PASSWORD action when explicitly assigning a non-temporary password.
            user.removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        }
    }

    private ErrorResponseException newUnauthorizedErrorResponseException(String oauthError, String errorMessage) {
        // See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
        response.getOutputHeaders().put(HttpHeaders.WWW_AUTHENTICATE, Collections.singletonList(String.format("Bearer realm=\"%s\", error=\"%s\", error_description=\"%s\"", realm.getName(), oauthError, errorMessage)));
        return new ErrorResponseException(oauthError, errorMessage, Response.Status.UNAUTHORIZED);
    }

    private Response issueUserInfo(String tokenString) {

        try {
            session.clientPolicy().triggerOnEvent(new UserInfoRequestContext(tokenString));
        } catch (ClientPolicyException cpe) {
            throw new ErrorResponseException(Errors.INVALID_REQUEST, cpe.getErrorDetail(), Response.Status.BAD_REQUEST);
        }

        EventBuilder event = new EventBuilder(realm, session, clientConnection)
                .event(EventType.USER_INFO_REQUEST)
                .detail(Details.AUTH_METHOD, Details.VALIDATE_ACCESS_TOKEN);

        if (tokenString == null) {
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Token not provided", Response.Status.BAD_REQUEST);
        }

        AccessToken token;
        ClientModel clientModel;
        try {
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class).withDefaultChecks()
                    .realmUrl(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));

            SignatureVerifierContext verifierContext = session.getProvider(SignatureProvider.class, verifier.getHeader().getAlgorithm().name()).verifier(verifier.getHeader().getKeyId());
            verifier.verifierContext(verifierContext);

            token = verifier.verify().getToken();

            clientModel = realm.getClientByClientId(token.getIssuedFor());
            if (clientModel == null) {
                event.error(Errors.CLIENT_NOT_FOUND);
                throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Client not found", Response.Status.BAD_REQUEST);
            }

            TokenVerifier.createWithoutSignature(token)
                    .withChecks(NotBeforeCheck.forModel(clientModel))
                    .verify();
        } catch (VerificationException e) {
            event.error(Errors.INVALID_TOKEN);
            throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_TOKEN, "Token verification failed");
        }

	    if (!clientModel.getProtocol().equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            event.error(Errors.INVALID_CLIENT);
            throw new ErrorResponseException(Errors.INVALID_CLIENT, "Wrong client protocol.", Response.Status.BAD_REQUEST);
        }

        session.getContext().setClient(clientModel);

        event.client(clientModel);

        if (!clientModel.isEnabled()) {
            event.error(Errors.CLIENT_DISABLED);
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Client disabled", Response.Status.BAD_REQUEST);
        }

        UserSessionModel userSession = findValidSession(token, event, clientModel);

        UserModel userModel = userSession.getUser();
        if (userModel == null) {
            event.error(Errors.USER_NOT_FOUND);
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "User not found", Response.Status.BAD_REQUEST);
        }

        event.user(userModel)
                .detail(Details.USERNAME, userModel.getUsername());

        // KEYCLOAK-6771 Certificate Bound Token
        // https://tools.ietf.org/html/draft-ietf-oauth-mtls-08#section-3
        if (OIDCAdvancedConfigWrapper.fromClientModel(clientModel).isUseMtlsHokToken()) {
            if (!MtlsHoKTokenUtil.verifyTokenBindingWithClientCertificate(token, request, session)) {
                event.error(Errors.NOT_ALLOWED);
                throw newUnauthorizedErrorResponseException(OAuthErrorException.UNAUTHORIZED_CLIENT, "Client certificate missing, or its thumbprint and one in the refresh token did NOT match");
            }
        }

        // Existence of authenticatedClientSession for our client already handled before
        AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(clientModel.getId());

        // Retrieve by latest scope parameter
        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession, session);

        AccessToken userInfo = new AccessToken();
        
        tokenManager.transformUserInfoAccessToken(session, userInfo, userSession, clientSessionCtx);

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userModel.getId());
        claims.putAll(userInfo.getOtherClaims());

        if (userInfo.getRealmAccess() != null) {
            Map<String, Set<String>> realmAccess = new HashMap<>();
            realmAccess.put("roles", userInfo.getRealmAccess().getRoles());
            claims.put("realm_access", realmAccess);
        }

        if (userInfo.getResourceAccess() != null && !userInfo.getResourceAccess().isEmpty()) {
            Map<String, Map<String, Set<String>>> resourceAccessMap = new HashMap<>();

            for (Map.Entry<String, AccessToken.Access> resourceAccessMapEntry : userInfo.getResourceAccess()
                    .entrySet()) {
                Map<String, Set<String>> resourceAccess = new HashMap<>();
                resourceAccess.put("roles", resourceAccessMapEntry.getValue().getRoles());
                resourceAccessMap.put(resourceAccessMapEntry.getKey(), resourceAccess);
            }
            claims.put("resource_access", resourceAccessMap);
        }

        Response.ResponseBuilder responseBuilder;
        OIDCAdvancedConfigWrapper cfg = OIDCAdvancedConfigWrapper.fromClientModel(clientModel);

        if (cfg.isUserInfoSignatureRequired()) {
            String issuerUrl = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
            String audience = clientModel.getClientId();
            claims.put("iss", issuerUrl);
            claims.put("aud", audience);

            String signatureAlgorithm = session.tokens().signatureAlgorithm(TokenCategory.USERINFO);

            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signatureAlgorithm);
            SignatureSignerContext signer = signatureProvider.signer();

            String signedUserInfo = new JWSBuilder().type("JWT").jsonContent(claims).sign(signer);

            responseBuilder = Response.ok(signedUserInfo).header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JWT);

            event.detail(Details.SIGNATURE_REQUIRED, "true");
            event.detail(Details.SIGNATURE_ALGORITHM, cfg.getUserInfoSignedResponseAlg().toString());
        } else {
            responseBuilder = Response.ok(claims).header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);

            event.detail(Details.SIGNATURE_REQUIRED, "false");
        }

        event.success();

        return Cors.add(request, responseBuilder).auth().allowedOrigins(session, clientModel).build();
    }

    private UserSessionModel findValidSession(AccessToken token, EventBuilder event, ClientModel client) {
        UserSessionModel userSession = new UserSessionCrossDCManager(session).getUserSessionWithClient(realm, token.getSessionState(), false, client.getId());
        UserSessionModel offlineUserSession = null;
        if (AuthenticationManager.isSessionValid(realm, userSession)) {
            checkTokenIssuedAt(token, userSession, event);
            event.session(userSession);
            return userSession;
        } else {
            offlineUserSession = new UserSessionCrossDCManager(session).getUserSessionWithClient(realm, token.getSessionState(), true, client.getId());
            if (AuthenticationManager.isOfflineSessionValid(realm, offlineUserSession)) {
                checkTokenIssuedAt(token, offlineUserSession, event);
                event.session(offlineUserSession);
                return offlineUserSession;
            }
        }

        if (userSession == null && offlineUserSession == null) {
            event.error(Errors.USER_SESSION_NOT_FOUND);
            throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_REQUEST, "User session not found or doesn't have client attached on it");
        }

        if (userSession != null) {
            event.session(userSession);
        } else {
            event.session(offlineUserSession);
        }

        event.error(Errors.SESSION_EXPIRED);
        throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_TOKEN, "Session expired");
    }

    private void checkTokenIssuedAt(AccessToken token, UserSessionModel userSession, EventBuilder event) throws ErrorResponseException {
        if (token.getIssuedAt() + 1 < userSession.getStarted()) {
            event.error(Errors.INVALID_TOKEN);
            throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_TOKEN, "Stale token");
        }
    }

    public static Response validateUserProfile(UserModel user, UserRepresentation rep, KeycloakSession session) {
        UserProfileValidationResult result = forUserResource(user, rep, session).validate();
        if (!result.getErrors().isEmpty()) {
            for (AttributeValidationResult attrValidation : result.getErrors()) {
                StringBuilder s = new StringBuilder("Failed to update attribute " + attrValidation.getField() + ": ");
                for (ValidationResult valResult : attrValidation.getFailedValidations()) {
                    s.append(valResult.getErrorType() + ", ");
                }
            }
            return ErrorResponse.error("Could not update user! See server log for more details", Response.Status.BAD_REQUEST);
        } else {
            return null;
        }
    }

    public static void updateUserFromRep(UserModel user, UserRepresentation rep, KeycloakSession session, boolean isUpdateExistingUser) {
        boolean removeMissingRequiredActions = isUpdateExistingUser;
        // UserUpdateHelper.updateUserResource(session, user, rep, rep.getAttributes() != null);
        UserUpdateHelper.updateUserResource(session, user, rep, false);

        if (rep.isEnabled() != null) user.setEnabled(rep.isEnabled());
        if (rep.isEmailVerified() != null) user.setEmailVerified(rep.isEmailVerified());

        if (rep.getFederationLink() != null) user.setFederationLink(rep.getFederationLink());

        List<String> reqActions = rep.getRequiredActions();

        if (reqActions != null) {
            Set<String> allActions = new HashSet<>();
            for (ProviderFactory factory : session.getKeycloakSessionFactory().getProviderFactories(RequiredActionProvider.class)) {
                allActions.add(factory.getId());
            }
            for (String action : allActions) {
                if (reqActions.contains(action)) {
                    user.addRequiredAction(action);
                } else if (removeMissingRequiredActions) {
                    user.removeRequiredAction(action);
                }
            }
        }

        List<CredentialRepresentation> credentials = rep.getCredentials();
        if (credentials != null) {
            for (CredentialRepresentation credential : credentials) {
                if (CredentialRepresentation.PASSWORD.equals(credential.getType()) && credential.isTemporary() != null
                        && credential.isTemporary()) {
                    user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                }
            }
        }
    }

    public static void updateUserRolesFromRep(UserModel user, UserRepresentation rep, RealmModel realm) {
        List<String> realmRoles = rep.getRealmRoles();
        if (realmRoles != null) {
            Iterator<RoleModel> itr = user.getRealmRoleMappingsStream().filter(r -> r.getName() != "offline_access" && r.getName() != "uma_authorization").iterator();
            while (itr.hasNext()) {
                RoleModel role = itr.next();
                user.deleteRoleMapping(role);
            }
            for (String roleString : realmRoles) {
                RoleModel role = realm.getRole(roleString.trim());
                if (role != null) { 
                    user.grantRole(role);
                }
            }
        }

        Map<String, List<String>> clientRoles = rep.getClientRoles();
        if (clientRoles != null) {
            for (Map.Entry<String, List<String>> entry : clientRoles.entrySet()) {
                ClientModel client = realm.getClientByClientId(entry.getKey());
                if (client == null) {
                    break;
                }
                for (String roleName : entry.getValue()) {
                    RoleModel role = client.getRole(roleName);
                    if (role != null) {
                        user.grantRole(role);
                    }
                }
            }
        }
    }

    private UserModel findValidUser(String tokenString) {
        try {
            session.clientPolicy().triggerOnEvent(new UserInfoRequestContext(tokenString));
        } catch (ClientPolicyException cpe) {
            throw new ErrorResponseException(Errors.INVALID_REQUEST, cpe.getErrorDetail(), Response.Status.BAD_REQUEST);
        }

        EventBuilder event = new EventBuilder(realm, session, clientConnection)
                .event(EventType.USER_INFO_REQUEST)
                .detail(Details.AUTH_METHOD, Details.VALIDATE_ACCESS_TOKEN);

        AccessToken token;
        ClientModel clientModel;
        try {
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class).withDefaultChecks()
                    .realmUrl(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        
            SignatureVerifierContext verifierContext = session.getProvider(SignatureProvider.class, verifier.getHeader().getAlgorithm().name()).verifier(verifier.getHeader().getKeyId());
            verifier.verifierContext(verifierContext);
        
            token = verifier.verify().getToken();
        
            clientModel = realm.getClientByClientId(token.getIssuedFor());
            if (clientModel == null) {
                event.error(Errors.CLIENT_NOT_FOUND);
                throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Client not found", Response.Status.BAD_REQUEST);
            }
        
            TokenVerifier.createWithoutSignature(token)
                    .withChecks(NotBeforeCheck.forModel(clientModel))
                    .verify();
        } catch (VerificationException e) {
            event.error(Errors.INVALID_TOKEN);
            throw newUnauthorizedErrorResponseException(OAuthErrorException.INVALID_TOKEN, "Token verification failed");
        }
        
        if (!clientModel.getProtocol().equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            event.error(Errors.INVALID_CLIENT);
            throw new ErrorResponseException(Errors.INVALID_CLIENT, "Wrong client protocol.", Response.Status.BAD_REQUEST);
        }
        
        session.getContext().setClient(clientModel);
        
        event.client(clientModel);
        
        if (!clientModel.isEnabled()) {
            event.error(Errors.CLIENT_DISABLED);
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Client disabled", Response.Status.BAD_REQUEST);
        }

        UserSessionModel userSession = findValidSession(token, event, clientModel);
        UserModel userModel = userSession.getUser();
        if (userModel == null) {
            event.error(Errors.USER_NOT_FOUND);
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "User not found", Response.Status.BAD_REQUEST);
        }
        return userModel;
    }
}
