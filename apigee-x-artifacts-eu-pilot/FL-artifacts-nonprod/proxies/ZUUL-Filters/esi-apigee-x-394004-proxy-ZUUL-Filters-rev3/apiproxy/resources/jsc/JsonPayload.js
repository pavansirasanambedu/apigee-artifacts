var responseJson = JSON.parse(context.getVariable("response.content"));
var cachekey = context.getVariable("session.id");
var statusCode = JSON.parse(context.getVariable("response.status"));
responseJson.statusCode = statusCode;
responseJson.cachekey = cachekey;
context.setVariable("response.content",JSON.stringify(responseJson));
context.setVariable("request.header.cachekey", "session.id");
