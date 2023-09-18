var responseJson = JSON.parse(context.getVariable("response.content"));
var sessionId = context.getVariable("session.id");
responseJson.sessionId = sessionId;
context.setVariable("response.content",JSON.stringify(responseJson));