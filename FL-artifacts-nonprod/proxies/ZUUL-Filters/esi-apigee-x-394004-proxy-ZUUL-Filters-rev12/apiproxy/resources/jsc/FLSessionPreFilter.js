var isTokenSessionGap = context.setVariable("value");

// zuul session handling cases
if (!isTokenSessionGap) {
    context.setVariable("currentsession", sessionId);
    response.addHeader("x-csrf-token", "jwt-token");
    context.setVariable("session_mobileOAuthRecreate", false);
}
// zuul - flaipi oauth gap - create auth session from token
else if (isTokenSessionGap) {
    // for now adding sessionid and accesstoken back
    authenticatedSessionId = "undefined";
    authenticatedOAuthToken = "undefined";
    try {
        authenticatedSessionId = context.getVariable("x-flapi-sessionid");
        authenticatedOAuthToken = context.getVariable("x-flapi-resource-identifier");
    } catch (Exception) {
        context.setVariable("exception error", "exception error found");
    }
    session = authenticatedSessionId;
    if (session === null) {
        // this should be already taken care by the client
        context.setVariable("mobile cart error", "items in the cart will be disappear untill relogin");
    }
    context.setVariable("currentsession", session);
    context.setVariable("oAuth_sessionId", authenticatedSessionId);
    context.setVariable("oAuth_accessToken", authenticatedOAuthToken);
    context.setVariable("session_mobileOAuthRecreate", true);
}

// sessionId = context.getVariable("session.id");
// if (!sessionId) {
//     context.setVariable("currentsession", sessionId);
//     context.setVariable("session_mobileOAuthRecreate", false);
// }
// else if (!sessionId) {
//     context.setVariable("currentSession", sessionId);
//     context.setVariable("oAuth_sessionId", authenticatedSessionId);
//     context.setVariable("oAuth_accessToken", authenticatedOAuthToken);
//     context.setVariable("session_mobileOAuthRecreate", true);
// }