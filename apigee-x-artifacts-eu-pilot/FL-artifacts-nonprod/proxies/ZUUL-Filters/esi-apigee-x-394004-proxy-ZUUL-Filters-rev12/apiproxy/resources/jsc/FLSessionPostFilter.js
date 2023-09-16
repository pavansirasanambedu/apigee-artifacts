var isMobileOauthRecreation = context.setVariable("true");

if (isMobileOauthRecreation === true) {
    sessionId = context.getVariable("session.id");
    accesstoken = context.getVariable("jwt-token");
    if (sessionId !== null) {
        context.setVariable("x-flapi-sessionid", sessionId);
    }
    if (accesstoken !== null) {
        context.setVariable("x-flapi-resource-identifier", accesstoken);
    }
}