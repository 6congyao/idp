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
package org.keycloak.services.resources.admin;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.Constants;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.policy.PasswordPolicyNotMetException;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserBatchRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.UserPermissionEvaluator;
import org.keycloak.storage.ReadOnlyException;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Base resource for managing users
 *
 * @resource Users
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UsersResource {

    private static final Logger logger = Logger.getLogger(UsersResource.class);
    private static final String SEARCH_ID_PARAMETER = "id:";
    private static final String DEFAULT_PASSWORD = "123456";
    private static final String DEFAULT_BATCH_CREATE_SEPARATOR = ",";

    protected RealmModel realm;

    private AdminPermissionEvaluator auth;

    private AdminEventBuilder adminEvent;

    @Context
    protected ClientConnection clientConnection;

    @Context
    protected KeycloakSession session;

    @Context
    protected HttpHeaders headers;

    public UsersResource(RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.auth = auth;
        this.realm = realm;
        this.adminEvent = adminEvent.resource(ResourceType.USER);
    }

    /**
     * Create a new user
     *
     * Username must be unique.
     *
     * @param rep
     * @return
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createUser(final UserRepresentation rep) {
        // first check if user has manage rights
        try {
            auth.users().requireManage();
        }
        catch (ForbiddenException exception) {
            // if user does not have manage rights, fallback to fine grain admin permissions per group
            if (rep.getGroups() != null) {
                // if groups is part of the user rep, check if admin has manage_members and manage_membership on each group
                for (String groupPath : rep.getGroups()) {
                    GroupModel group = KeycloakModelUtils.findGroupByPath(realm, groupPath);
                    if (group != null) {
                        auth.groups().requireManageMembers(group);
                        auth.groups().requireManageMembership(group);
                    } else {
                        return ErrorResponse.error(String.format("Group %s not found", groupPath), Response.Status.BAD_REQUEST);
                    }
                }
            } else {
                // propagate exception if no group specified
                throw exception;
            }
        }

        String username = rep.getUsername();
        if(realm.isRegistrationEmailAsUsername()) {
            username = rep.getEmail();
        }
        if (ObjectUtil.isBlank(username)) {
            return ErrorResponse.error("User name is missing", Response.Status.BAD_REQUEST);
        }

        // Double-check duplicated username and email here due to federation
        if (session.users().getUserByUsername(username, realm) != null) {
            return ErrorResponse.exists("User exists with same username");
        }
        if (rep.getEmail() != null && !realm.isDuplicateEmailsAllowed()) {
            try {
                if(session.users().getUserByEmail(rep.getEmail(), realm) != null) {
                    return ErrorResponse.exists("User exists with same email");
                }
            } catch (ModelDuplicateException e) {
                return ErrorResponse.exists("User exists with same email");
            }
        }

        try {
            Response response = UserResource.validateUserProfile(null, rep, session);
            if (response != null) {
                return response;
            }

            UserModel user = session.users().addUser(realm, username);

            UserResource.updateUserFromRep(user, rep, session, false);
            UserResource.updateUserRolesFromRep(user, rep, realm);
            RepresentationToModel.createFederatedIdentities(rep, session, realm, user);
            RepresentationToModel.updateGroups(rep, realm, user);

            RepresentationToModel.createCredentials(rep, session, realm, user, true);
            adminEvent.operation(OperationType.CREATE).resourcePath(session.getContext().getUri(), user.getId()).representation(rep).success();

            if (session.getTransactionManager().isActive()) {
                session.getTransactionManager().commit();
            }

            return Response.created(session.getContext().getUri().getAbsolutePathBuilder().path(user.getId()).build()).build();
        } catch (ModelDuplicateException e) {
            if (session.getTransactionManager().isActive()) {
                session.getTransactionManager().setRollbackOnly();
            }
            return ErrorResponse.exists("User exists with same username or email");
        } catch (PasswordPolicyNotMetException e) {
            if (session.getTransactionManager().isActive()) {
                session.getTransactionManager().setRollbackOnly();
            }
            return ErrorResponse.error("Password policy not met", Response.Status.BAD_REQUEST);
        } catch (ModelException me){
            if (session.getTransactionManager().isActive()) {
                session.getTransactionManager().setRollbackOnly();
            }
            logger.warn("Could not create user", me);
            return ErrorResponse.error("Could not create user", Response.Status.BAD_REQUEST);
        }
    }
    /**
     * Get representation of the user
     *
     * @param id User id or user name
     * @return
     */
    @Path("{id}")
    public UserResource user(final @PathParam("id") String id) {
        UserModel user = session.users().getUserById(id, realm);
        if (user == null) {
            user = session.users().getUserByUsername(id, realm);
            if (user == null) {
                // we do this to make sure somebody can't phish ids
                if (auth.users().canQuery()) throw new NotFoundException("User not found");
                else throw new ForbiddenException();
            }
        }
        UserResource resource = new UserResource(realm, user, auth, adminEvent);
        ResteasyProviderFactory.getInstance().injectProperties(resource);
        //resourceContext.initResource(users);
        return resource;
    }

    /**
     * Get users
     *
     * Returns a stream of users, filtered according to query parameters
     *
     * @param search A String contained in username, first or last name, or email
     * @param last A String contained in lastName, or the complete lastName, if param "exact" is true
     * @param first A String contained in firstName, or the complete firstName, if param "exact" is true
     * @param email A String contained in email, or the complete email, if param "exact" is true
     * @param username A String contained in username, or the complete username, if param "exact" is true
     * @param emailVerified whether the email has been verified
     * @param idpAlias The alias of an Identity Provider linked to the user
     * @param idpUserId The userId at an Identity Provider linked to the user
     * @param firstResult Pagination offset
     * @param maxResults Maximum results size (defaults to 100)
     * @param enabled Boolean representing if user is enabled or not
     * @param briefRepresentation Boolean which defines whether brief representations are returned (default: false)
     * @param exact Boolean which defines whether the params "last", "first", "email" and "username" must match exactly
     * @return a non-null {@code Stream} of users
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Stream<UserRepresentation> getUsers(@QueryParam("search") String search,
                                               @QueryParam("lastName") String last,
                                               @QueryParam("firstName") String first,
                                               @QueryParam("email") String email,
                                               @QueryParam("username") String username,
                                               @QueryParam("emailVerified") Boolean emailVerified,
                                               @QueryParam("idpAlias") String idpAlias,
                                               @QueryParam("idpUserId") String idpUserId,
                                               @QueryParam("offset") Integer firstResult,
                                               @QueryParam("limit") Integer maxResults,
                                               @QueryParam("enabled") Boolean enabled,
                                               @QueryParam("briefRepresentation") Boolean briefRepresentation,
                                               @QueryParam("exact") Boolean exact) {
        UserPermissionEvaluator userPermissionEvaluator = auth.users();

        userPermissionEvaluator.requireQuery();

        firstResult = firstResult != null ? firstResult : -1;
        maxResults = maxResults != null ? maxResults : Constants.DEFAULT_MAX_RESULTS;

        Stream<UserModel> userModels = Stream.empty();
        if (search != null) {
            if (search.startsWith(SEARCH_ID_PARAMETER)) {
                UserModel userModel =
                        session.users().getUserById(search.substring(SEARCH_ID_PARAMETER.length()).trim(), realm);
                if (userModel != null) {
                    userModels = Stream.of(userModel);
                }
            } else {
                Map<String, String> attributes = new HashMap<>();
                attributes.put(UserModel.SEARCH, search.trim());
                if (enabled != null) {
                    attributes.put(UserModel.ENABLED, enabled.toString());
                }
                return searchForUser(attributes, realm, userPermissionEvaluator, briefRepresentation, firstResult,
                        maxResults, false);
            }
        } else if (last != null || first != null || email != null || username != null || emailVerified != null
                || idpAlias != null || idpUserId != null || enabled != null || exact != null) {
                    Map<String, String> attributes = new HashMap<>();
                    if (last != null) {
                        attributes.put(UserModel.LAST_NAME, last);
                    }
                    if (first != null) {
                        attributes.put(UserModel.FIRST_NAME, first);
                    }
                    if (email != null) {
                        attributes.put(UserModel.EMAIL, email);
                    }
                    if (username != null) {
                        attributes.put(UserModel.USERNAME, username);
                    }
                    if (emailVerified != null) {
                        attributes.put(UserModel.EMAIL_VERIFIED, emailVerified.toString());
                    }
                    if (idpAlias != null) {
                        attributes.put(UserModel.IDP_ALIAS, idpAlias);
                    }
                    if (idpUserId != null) {
                        attributes.put(UserModel.IDP_USER_ID, idpUserId);
                    }
                    if (enabled != null) {
                        attributes.put(UserModel.ENABLED, enabled.toString());
                    }
                    if (exact != null) {
                        attributes.put(UserModel.EXACT, exact.toString());
                    }
                    return searchForUser(attributes, realm, userPermissionEvaluator, briefRepresentation, firstResult,
                            maxResults, true);
                } else {
                    return searchForUser(new HashMap<>(), realm, userPermissionEvaluator, briefRepresentation,
                            firstResult, maxResults, false);
                }

        return toRepresentation(realm, userPermissionEvaluator, briefRepresentation, userModels);
    }

    /**
     * Returns the number of users that match the given criteria.
     * It can be called in three different ways.
     * 1. Don't specify any criteria and pass {@code null}. The number of all
     * users within that realm will be returned.
     * <p>
     * 2. If {@code search} is specified other criteria such as {@code last} will
     * be ignored even though you set them. The {@code search} string will be
     * matched against the first and last name, the username and the email of a
     * user.
     * <p>
     * 3. If {@code search} is unspecified but any of {@code last}, {@code first},
     * {@code email} or {@code username} those criteria are matched against their
     * respective fields on a user entity. Combined with a logical and.
     *
     * @param search   arbitrary search string for all the fields below
     * @param last     last name filter
     * @param first    first name filter
     * @param email    email filter
     * @param username username filter
     * @return the number of users that match the given criteria
     */
    @Path("count")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Integer getUsersCount(@QueryParam("search") String search,
                                 @QueryParam("lastName") String last,
                                 @QueryParam("firstName") String first,
                                 @QueryParam("email") String email,
                                 @QueryParam("emailVerified") Boolean emailVerified,
                                 @QueryParam("username") String username) {
        UserPermissionEvaluator userPermissionEvaluator = auth.users();
        userPermissionEvaluator.requireQuery();

        if (search != null) {
            if (search.startsWith(SEARCH_ID_PARAMETER)) {
                UserModel userModel = session.users().getUserById(search.substring(SEARCH_ID_PARAMETER.length()).trim(), realm);
                return userModel != null && userPermissionEvaluator.canView(userModel) ? 1 : 0;
            } else if (userPermissionEvaluator.canView()) {
                return session.users().getUsersCount(search.trim(), realm);
            } else {
                return session.users().getUsersCount(search.trim(), realm, auth.groups().getGroupsWithViewPermission());
            }
        } else if (last != null || first != null || email != null || username != null || emailVerified != null) {
            Map<String, String> parameters = new HashMap<>();
            if (last != null) {
                parameters.put(UserModel.LAST_NAME, last);
            }
            if (first != null) {
                parameters.put(UserModel.FIRST_NAME, first);
            }
            if (email != null) {
                parameters.put(UserModel.EMAIL, email);
            }
            if (username != null) {
                parameters.put(UserModel.USERNAME, username);
            }
            if (emailVerified != null) {
                parameters.put(UserModel.EMAIL_VERIFIED, emailVerified.toString());
            }
            if (userPermissionEvaluator.canView()) {
                return session.users().getUsersCount(parameters, realm);
            } else {
                return session.users().getUsersCount(parameters, realm, auth.groups().getGroupsWithViewPermission());
            }
        } else if (userPermissionEvaluator.canView()) {
            return session.users().getUsersCount(realm);
        } else {
            return session.users().getUsersCount(realm, auth.groups().getGroupsWithViewPermission());
        }
    }

    private Stream<UserRepresentation> searchForUser(Map<String, String> attributes, RealmModel realm, UserPermissionEvaluator usersEvaluator, Boolean briefRepresentation, Integer firstResult, Integer maxResults, Boolean includeServiceAccounts) {
        session.setAttribute(UserModel.INCLUDE_SERVICE_ACCOUNT, includeServiceAccounts);

        if (!auth.users().canView()) {
            Set<String> groupModels = auth.groups().getGroupsWithViewPermission();

            if (!groupModels.isEmpty()) {
                session.setAttribute(UserModel.GROUPS, groupModels);
            }
        }

        Stream<UserModel> userModels = session.users().searchForUserStream(attributes, realm, firstResult, maxResults);
        return toRepresentation(realm, usersEvaluator, briefRepresentation, userModels);
    }

    private Stream<UserRepresentation> toRepresentation(RealmModel realm, UserPermissionEvaluator usersEvaluator, Boolean briefRepresentation, Stream<UserModel> userModels) {
        boolean briefRepresentationB = briefRepresentation != null && briefRepresentation;
        boolean canViewGlobal = usersEvaluator.canView();

        usersEvaluator.grantIfNoPermission(session.getAttribute(UserModel.GROUPS) != null);
        return userModels.filter(user -> canViewGlobal || usersEvaluator.canView(user))
                .map(user -> {
                    UserRepresentation userRep = briefRepresentationB
                            ? ModelToRepresentation.toBriefRepresentation(user)
                            : ModelToRepresentation.toRepresentation(session, realm, user);
                    userRep.setAccess(usersEvaluator.getAccess(user));
                    return userRep;
                });
    }

    @Path("batch")
    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response operateBatchUsers(final UserBatchRepresentation rep) {
        // first check if user has manage rights
        auth.users().requireManage();

        List<String> creates = rep.getCreate();
        if (creates != null) {
            for (String userCSV : creates) {
                UserRepresentation userRep = getUserRepWithCSV(userCSV);
                if (userRep == null) {
                    continue;
                }
                try {
                    Response response = UserResource.validateUserProfile(null, userRep, session);
                    if (response != null) {
                        return response;
                    }
        
                    UserModel user = session.users().addUser(realm, userRep.getUsername());
        
                    UserResource.updateUserFromRep(user, userRep, session, false);
                    UserResource.updateUserRolesFromRep(user, userRep, realm);
                    RepresentationToModel.createFederatedIdentities(userRep, session, realm, user);
                    RepresentationToModel.updateGroups(userRep, realm, user);
        
                    RepresentationToModel.createCredentials(userRep, session, realm, user, true);
                    adminEvent.operation(OperationType.CREATE).resourcePath(session.getContext().getUri(), user.getId()).representation(userRep).success();
        
                } catch (ModelDuplicateException e) {
                    if (session.getTransactionManager().isActive()) {
                        session.getTransactionManager().setRollbackOnly();
                    }
                    return ErrorResponse.exists("User exists with same username or email:" + userRep.getUsername());
                } catch (PasswordPolicyNotMetException e) {
                    if (session.getTransactionManager().isActive()) {
                        session.getTransactionManager().setRollbackOnly();
                    }
                    return ErrorResponse.error("Password policy not met", Response.Status.BAD_REQUEST);
                } catch (ModelException me){
                    if (session.getTransactionManager().isActive()) {
                        session.getTransactionManager().setRollbackOnly();
                    }
                    logger.warn("Could not create user", me);
                    return ErrorResponse.error("Could not create user:" + userRep.getUsername(), Response.Status.BAD_REQUEST);
                }
            }
            if (session.getTransactionManager().isActive()) {
                session.getTransactionManager().commit();
            }
        }

        List<String> deletes = rep.getDelete();
        if (deletes != null) {
            for (String uid : deletes) {
                UserModel user = session.users().getUserById(uid, realm);
                if (user == null) {
                    user = session.users().getUserByUsername(uid, realm);
                }
                if (user != null) {
                    boolean removed = session.users().removeUser(realm, user);
                    if (removed) {
                        adminEvent.operation(OperationType.DELETE).resourcePath(session.getContext().getUri()).success();
                    }
                } else {
                    return ErrorResponse.error(String.format("User %s not found", uid), Response.Status.BAD_REQUEST);
                }
            }
        }

        List<String> resets = rep.getReset();
        if (resets != null) {
            for (String uid : resets) {
                UserModel user = session.users().getUserById(uid, realm);
                if (user == null) {
                    user = session.users().getUserByUsername(uid, realm);
                }
                if (user != null) {
                    try {
                        session.userCredentialManager().updateCredential(realm, user, UserCredentialModel.password(DEFAULT_PASSWORD, false));
                        adminEvent.operation(OperationType.ACTION).resourcePath(session.getContext().getUri()).success();
                    } catch (IllegalStateException ise) {
                        throw new BadRequestException("Resetting to N old passwords is not allowed.");
                    } catch (ReadOnlyException mre) {
                        throw new BadRequestException("Can't reset password as account is read only");
                    } catch (ModelException e) {
                        logger.warn("Could not update user password.", e);
                        Properties messages = AdminRoot.getMessages(session, realm, auth.adminAuth().getToken().getLocale());
                        throw new ErrorResponseException(e.getMessage(), MessageFormat.format(messages.getProperty(e.getMessage(), e.getMessage()), e.getParameters()),
                            Response.Status.BAD_REQUEST);
                    }
                } else {
                    return ErrorResponse.error(String.format("User %s not found", uid), Response.Status.BAD_REQUEST);
                }
            }
        }

        return null;
    }

    private UserRepresentation getUserRepWithCSV(String csv) {
        UserRepresentation rep = new UserRepresentation();

        String[] userSegments = csv.split(DEFAULT_BATCH_CREATE_SEPARATOR, -1);
        if (ObjectUtil.isBlank(userSegments[0])) {
            return null;
        }
        rep.setUsername(userSegments[0].trim());

        if (!ObjectUtil.isBlank(userSegments[1])) {
            rep.setFirstName(userSegments[1].trim());
        }

        if (!ObjectUtil.isBlank(userSegments[2])) {
            List<String> groups = new ArrayList<>();
            groups.add(userSegments[2].trim());
            rep.setGroups(groups);
        }
        
        List<String> roles = new ArrayList<>();
        for (int i = 3; i < userSegments.length; i++) {
            if (!ObjectUtil.isBlank(userSegments[i])) {
                roles.add(userSegments[i].trim());
            }
        }
        // List<String> roles = Arrays.asList(Arrays.copyOfRange(userSegments, 3, userSegments.length));
        rep.setRealmRoles(roles);

        rep.setEnabled(true);

        CredentialRepresentation cr = new CredentialRepresentation();
        cr.setType("password");
        cr.setValue(DEFAULT_PASSWORD);
        cr.setTemporary(false);
        List<CredentialRepresentation> crs = new ArrayList<>();
        crs.add(cr);

        rep.setCredentials(crs);
        return rep;
    }
}
