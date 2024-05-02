package org.keycloak.authentication.authenticators.conditional;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import jakarta.ws.rs.core.MultivaluedMap;

public class ConditionalHeaderAuthenticator implements ConditionalAuthenticator {
    public static final ConditionalHeaderAuthenticator SINGLETON = new ConditionalHeaderAuthenticator();

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        boolean negateOutput = Boolean.parseBoolean(config.get(ConditionalUserAttributeValueFactory.CONF_NOT));
        boolean regexOutput = Boolean.parseBoolean(config.get(ConditionalUserAttributeValueFactory.REGEX));
        String headerName = config.get(ConditionalHeaderAuthenticatorFactory.HEADER_NAME);
        String headerValue = config.get(ConditionalHeaderAuthenticatorFactory.HEADER_VALUE);
        MultivaluedMap<String, String> requestHeaders = context.getHttpRequest().getHttpHeaders().getRequestHeaders();

        if (regexOutput) {
            return matchUsingRegex(requestHeaders, headerName, headerValue) ^ negateOutput;
        } else {
            return matchSimple(requestHeaders, headerName, headerValue) ^ negateOutput;
        }
    }

    private static boolean matchSimple(MultivaluedMap<String, String> requestHeaders, String headerName,
            String headerValue) {
        List<String> values = requestHeaders.get(headerName);

        if (headerValue == null || headerValue.isEmpty() || values == null || values.isEmpty()) {
            return false;
        }

        for (String value : values) {
            if (Objects.equals(value, headerValue)) {
                return true;
            }
        }

        return false;
    }

    private static boolean matchUsingRegex(MultivaluedMap<String, String> requestHeaders, String headerName,
            String headerValue) {
        List<String> values = requestHeaders.get(headerName);

        if (headerValue == null || headerValue.isEmpty() || values == null || values.isEmpty()) {
            return false;
        }

        Pattern pattern = Pattern.compile(headerValue, Pattern.DOTALL);

        for (String value : values) {
            if (pattern.matcher(value).matches()) {
                return true;
            }
        }

        return false;
    }

    @Override
    public void close() {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }
}
