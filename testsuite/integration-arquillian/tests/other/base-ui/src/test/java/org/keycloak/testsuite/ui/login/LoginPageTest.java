/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.ui.login;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.auth.page.login.Registration;
import org.keycloak.testsuite.auth.page.login.ResetCredentials;
import org.keycloak.testsuite.auth.page.login.UpdateAccount;
import org.keycloak.testsuite.auth.page.login.UpdatePassword;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.keycloak.testsuite.auth.page.AuthRealm.TEST;
import static org.keycloak.testsuite.util.URLAssert.assertCurrentUrlStartsWithLoginUrlOf;

/**
 * @author Vaclav Muzikar <vmuzikar@redhat.com>
 */
public class LoginPageTest extends AbstractLoginTest {
    @Page
    private UpdateAccount updateAccountPage;

    @Page
    private UpdatePassword updatePasswordPage;

    @Page
    private Registration registrationPage;

    @Page
    private ResetCredentials resetCredentialsPage;

    @Override
    public void setDefaultPageUriParameters() {
        super.setDefaultPageUriParameters();
        updateAccountPage.setAuthRealm(TEST);
        updatePasswordPage.setAuthRealm(TEST);
        registrationPage.setAuthRealm(TEST);
        resetCredentialsPage.setAuthRealm(TEST);
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        super.addTestRealms(testRealms);
        RealmRepresentation testRealmRep = testRealms.get(0);
        testRealmRep.setDisplayNameHtml("Test realm <b>HTML</b>");
        testRealmRep.setRememberMe(true);
        testRealmRep.setResetPasswordAllowed(true);
        testRealmRep.setRegistrationAllowed(true);
    }

    @Before
    public void beforeLoginTest() {
        deleteAllCookiesForTestRealm();
        testRealmAccountPage.navigateTo();
        assertCurrentUrlStartsWithLoginUrlOf(testRealmAccountPage);
        assertFalse(testRealmLoginPage.feedbackMessage().isPresent());
    }

    @Test
    public void wrongCredentials() {
        assertFalse(testRealmLoginPage.form().isRememberMe());
        testRealmLoginPage.form().rememberMe(true);
        assertTrue(testRealmLoginPage.form().isRememberMe());
        testRealmLoginPage.form().login("some-user", "badPwd");
        assertTrue(testRealmLoginPage.form().isRememberMe());

        assertLoginFailed("Invalid username or password.");
    }

    @Test
    public void disabledUser() {
        testUser.setEnabled(false);
        testUserResource().update(testUser);

        testRealmLoginPage.form().login(testUser);

        assertLoginFailed("Account is disabled, contact your administrator.");
    }

    @Test
    public void labelsTest() {
        assertEquals("test realm html", testRealmLoginPage.getHeaderText().toLowerCase()); // we need to convert to lower case as Safari handles getText() differently
        assertEquals("Username or email", testRealmLoginPage.form().getUsernameLabel());
        assertEquals("Password", testRealmLoginPage.form().getPasswordLabel());
    }

    @Test
    public void loginSuccessful() {
        testRealmLoginPage.form().login(testUser);
        assertLoginSuccessful();
    }

    @Test
    public void internationalizationTest() {
        final String rememberMeLabel = "[TEST LOCALE] Zapamatuj si m??";

        // required action set up
        testUser.setRequiredActions(Arrays.asList(updatePasswordPage.getActionId(), updateAccountPage.getActionId()));
        testUserResource().update(testUser);

        assertEquals("Remember me", testRealmLoginPage.form().getRememberMeLabel());
        testRealmLoginPage.localeDropdown().selectByText(CUSTOM_LOCALE_NAME);
        assertEquals(rememberMeLabel, testRealmLoginPage.form().getRememberMeLabel());

        testRealmLoginPage.form().login();
        assertLoginFailed("[TEST LOCALE] Chybn?? jm??no nebo heslo");
        assertEquals(rememberMeLabel, testRealmLoginPage.form().getRememberMeLabel());
        testRealmLoginPage.form().login(testUser);

        if (updatePasswordPage.isCurrent()) {
            updatePassword();
            updateProfile();
        }
        else {
            updateProfile();
            updatePassword();
        }

        assertLoginSuccessful();
    }

    private void updateProfile() {
        assertEquals("[TEST LOCALE] aktualizovat profil", updateAccountPage.feedbackMessage().getText());
        updateAccountPage.submit(); // should be pre-filled
    }

    private void updatePassword() {
        updatePasswordPage.updatePasswords("some wrong", "password");
        assertEquals("[TEST LOCALE] hesla se neshoduj??", updatePasswordPage.feedbackMessage().getText());
        updatePasswordPage.updatePasswords("matchingPassword", "matchingPassword");
    }

    @Test
    public void registerTest() {
        testRealmLoginPage.form().register();

        registrationPage.assertCurrent();

        registrationPage.localeDropdown().selectByText(CUSTOM_LOCALE_NAME);
        registrationPage.submit();

        assertTrue(registrationPage.feedbackMessage().isError());
        assertEquals("[TEST LOCALE] k??estn?? jm??no", registrationPage.accountFields().getFirstNameLabel());

        registrationPage.backToLogin();
        testRealmLoginPage.form().register();

        registrationPage.localeDropdown().selectByText(ENGLISH_LOCALE_NAME);

        final String username = "vmuzikar";
        final String email = "vmuzikar@redhat.com";
        final String firstName = "Vaclav";
        final String lastName = "Muzikar";
        final  UserRepresentation newUser = createUserRepresentation(username, email, firstName, lastName, true, "password");
        
        // empty form
        registrationPage.submit();
        assertRegistrationFields(null, null, null, null, false, true);

        // email filled in
        registrationPage.accountFields().setEmail(email);
        registrationPage.submit();
        assertRegistrationFields(null, null, email, null, false, true);

        // first name filled in
        registrationPage.accountFields().setEmail(null);
        registrationPage.accountFields().setFirstName(firstName);
        registrationPage.submit();
        assertRegistrationFields(firstName, null, null, null, false, true);

        // last name filled in
        registrationPage.accountFields().setFirstName(null);
        registrationPage.accountFields().setLastName(lastName);
        registrationPage.submit();
        assertRegistrationFields(null, lastName, null, null, false, true);

        // username filled in
        registrationPage.accountFields().setLastName(null);
        registrationPage.accountFields().setUsername(username);
        registrationPage.submit();
        assertRegistrationFields(null, null, null, username, false, true);

        // password mismatch
        registrationPage.accountFields().setValues(newUser);
        registrationPage.passwordFields().setPassword("wrong");
        registrationPage.passwordFields().setConfirmPassword("password");
        registrationPage.submit();
        assertRegistrationFields(firstName, lastName, email, username, true, false);

        // success
        registrationPage.register(newUser);
        assertLoginSuccessful();
    }

    private void assertRegistrationFields(String firstName, String lastName, String email, String username, boolean password, boolean passwordConfirm) {
        assertTrue(registrationPage.feedbackMessage().isError());

        assertRegistrationAvailability(firstName != null, registrationPage.accountFields().hasFirstNameError(),
                firstName, registrationPage.accountFields().getFirstName());

        assertRegistrationAvailability(lastName != null, registrationPage.accountFields().hasLastNameError(),
                lastName, registrationPage.accountFields().getLastName());

        assertRegistrationAvailability(email != null, registrationPage.accountFields().hasEmailError(),
                email, registrationPage.accountFields().getEmail());

        assertRegistrationAvailability(username != null, registrationPage.accountFields().hasUsernameError(),
                username, registrationPage.accountFields().getUsername());

        assertRegistrationAvailability(password, registrationPage.passwordFields().hasPasswordError());
        assertRegistrationAvailability(passwordConfirm, registrationPage.passwordFields().hasConfirmPasswordError());
    }

    private void assertRegistrationAvailability(boolean isAvailable, boolean state) {
        assertRegistrationAvailability(isAvailable, state, null, null);
    }

    private void assertRegistrationAvailability(boolean isAvailable, boolean state, String expected, String actual) {
        if (isAvailable) {
            assertFalse(state);
            if (expected != null && actual != null) {
                assertEquals(expected, actual);
            }
        } else {
            assertTrue(state);
        }
    }

    @Test
    public void resetCredentialsTest() {
        testRealmLoginPage.form().forgotPassword();
        resetCredentialsPage.localeDropdown().selectByText(CUSTOM_LOCALE_NAME);
        resetCredentialsPage.assertCurrent();
        resetCredentialsPage.backToLogin();

        testRealmLoginPage.form().forgotPassword();
        assertEquals("[TEST LOCALE] Zapomenut?? heslo", resetCredentialsPage.getTitleText());

        // empty form
        assertFalse(resetCredentialsPage.feedbackMessage().isPresent());
        resetCredentialsPage.submit();
        resetCredentialsPage.assertCurrent();
        assertTrue(resetCredentialsPage.feedbackMessage().isPresent());
        assertTrue(resetCredentialsPage.feedbackMessage().isError());

        // non-empty form
        resetCredentialsPage.resetCredentials(testUser.getUsername());
        // there will be probably an error sending email, so no further action here
    }
}
