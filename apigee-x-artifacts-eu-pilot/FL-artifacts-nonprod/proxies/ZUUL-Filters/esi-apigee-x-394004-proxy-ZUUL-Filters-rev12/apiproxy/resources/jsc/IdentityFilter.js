session = context.getVariable("currentsession");
userType = context.setVariable("registered");
isAuthenticated = context.setVariable("true");
var authHeader = context.getVariable("request.header.jwt-token");
guestId = Math.random().toString(36).substring(2);
var guestId = context.setVariable("guestId", guestId);


if (isAuthenticated) {
    userId = Math.random().toString(36).substring(2);
    context.setVariable("userId", userId);
    // add to zuul headers
    if ((authHeader !== null) && (guestId !== null)) {
        // add to zuul headers
    }
}
else {
    isSessionAwareRoute = context.setVariable("true");
    if (isSessionAwareRoute) {
        if ((authHeader === null) || (guestId === null)) {
            context.setVariable("undefined guest id", "undefined guest id, 404 error.")
        }
        // add current userId name and guestId into zuul headers
    }
    else {
        // add current userId name, token.guestId into zuul headers
    }
}

// add currentSessionId and sessionId.name into zuul headers



















// var username = context.setVariable("request.header.username", "username");
// var password = context.setVariable("request.header.password", "password");
// if (username == "username") {
//     isauthenticated = true;
//     var registeredId = Math.random().toString(36).substring(2);
//     context.setVariable("register.id", registeredId);
//     // console.log("registered user");
// }
// else {
//     var guestId = Math.random().toString(36).substring(2);
//     context.setVariable("guest.id", guestId);
//     // console.log("undefined user");
//     if (guestId === null) {
//         context.setVariable("InvalidguestId", "400 error guestId not found");
//     }
// }