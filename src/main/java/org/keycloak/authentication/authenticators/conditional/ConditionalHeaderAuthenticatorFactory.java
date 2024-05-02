package org.keycloak.authentication.authenticators.conditional;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

public class ConditionalHeaderAuthenticatorFactory implements AuthenticatorFactory {
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    public static final String HEADER_NAME = "headerName";
    public static final String HEADER_VALUE = "headerValue";
    public static final String NEGATE = "negate";
    public static final String REGEX = "regex";

    public static final String PROVIDER_ID = "conditional-header";

    @Override
    public String getHelpText() {
        return "Conditional authenticator which matches request headers.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty headerName = new ProviderConfigProperty();
        headerName.setType(ProviderConfigProperty.STRING_TYPE);
        headerName.setName(HEADER_NAME);
        headerName.setRequired(true);
        headerName.setLabel("Header name");
        headerName.setHelpText(
                "HTTP request header name that must match to execute this flow.");

        ProviderConfigProperty headerValue = new ProviderConfigProperty();
        headerValue.setType(ProviderConfigProperty.STRING_TYPE);
        headerValue.setName(HEADER_VALUE);
        headerValue.setRequired(true);
        headerValue.setLabel("Expected header value");
        headerValue.setHelpText("Expected value in the HTTP request header");

        ProviderConfigProperty negateOutput = new ProviderConfigProperty();
        negateOutput.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        negateOutput.setName(NEGATE);
        negateOutput.setLabel("Negate output");
        negateOutput.setHelpText(
                "Apply a NOT to the check result. When this is true, then the condition will evaluate to true just if request headers do NOT match. When this is false, the condition will evaluate to true just if request headers do match");

        ProviderConfigProperty regexOutput = new ProviderConfigProperty();
        regexOutput.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        regexOutput.setName(REGEX);
        regexOutput.setLabel("Regex");
        regexOutput.setHelpText("Check equality with regex");

        return Arrays.asList(headerName, headerValue, negateOutput, regexOutput);
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void close() {
    }

    @Override
    public String getDisplayType() {
        return "Condition - Request Headers";
    }

    @Override
    public String getReferenceCategory() {
        return "condition";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return ConditionalHeaderAuthenticator.SINGLETON;
    }
}