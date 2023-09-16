var responseJson = JSON.parse(context.getVariable("response.content"));
// var statusCode = context.setVariable("statusCode","200");
context.setVariable("response.content",JSON.stringify(responseJson));

if ((response.content) !== null) {
    context.setVariable("response.status.code", 200);
}
else {
    context.setVariable("response.status.code", "check the error");
}