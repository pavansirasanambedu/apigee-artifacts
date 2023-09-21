var authHeader = context.getVariable("request.header.jwt-token");
var sessionId = context.getVariable("session.id");
if ( !authHeader) {
    throw "error";
}
if ( !sessionId) {
    throw "error";
}