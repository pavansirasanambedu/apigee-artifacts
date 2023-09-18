var username = context.setVariable("request.header.username", "username");
var password = context.setVariable("request.header.password", "password");
if (username == "username") {
    isauthenticated = true;
    var registeredId = Math.random().toString(36).substring(2);
    context.setVariable("register.id", registeredId);
    console.log("registered user");
}
else {
    var guestId = Math.random().toString(36).substring(2);
    context.setVariable("guest.id", guestId);
    console.log("undefined user");
    if (guestId === null) {
        context.setVariable("InvalidguestId", "400 error guestId not found");
    }
}