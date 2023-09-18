sessionId = context.getVariable("session.id");
if (!sessionId) {
    context.setVariable("currentsession", sessionId);
    context.setVariable("session_mobileOAuthRecreate", false);
}
else if (!sessionId) {
    context.setVariable("currentSession", sessionId);
    context.setVariable("oAuth_sessionId", authenticatedSessionId);
    context.setVariable("oAuth_accessToken", authenticatedOAuthToken);
    context.setVariable("session_mobileOAuthRecreate", true);
}