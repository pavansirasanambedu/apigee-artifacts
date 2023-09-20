var authHeader = context.getVariable("request.header.jwt-token");
var sessionId = context.getVariable("session.id");
var devicetype = context.setVariable("web");
var issessionawarepath = context.setVariable("ctx");
var method = context.getVariable(request.verb)
 

if ((devicetype === "web") &&  (authHeader !== null) && (sessionId !== null)) {
    if (issessionawarepath === "ctx") {
        if (method === "GET") {
            print("session awarepath has no client identity");
            context.setVariable("error1", "session awarepath has no client identity");
        }
    }
}
else {
    print(null)
}
    
// if ( !authHeader) {
//     context.setVariable("authHeader", "authHeader is not found");
//     throw "error";
    
// }
// if ( !sessionId) {
//     context.setVariable("sessionerror", "sessionId is not found");
//     throw "error";
// }