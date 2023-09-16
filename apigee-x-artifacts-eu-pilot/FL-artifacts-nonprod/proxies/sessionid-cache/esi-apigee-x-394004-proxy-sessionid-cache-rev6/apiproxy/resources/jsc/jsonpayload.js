var responseJson = JSON.parse(context.getVariable("response.content"));
var cachekey = context.getVariable("session.id");
responseJson.cachekey = cachekey;
context.setVariable("response.content",JSON.stringify(responseJson));