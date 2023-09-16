var responseJson = JSON.parse(context.getVariable("response.content"));
var sessionId = context.getVariable("session.id");
var statusCode = "200";
responseJson.statuscode = statusCode;
responseJson.sessionId = sessionId;
print(statusCode);
context.setVariable("response.content", JSON.stringify(responseJson));