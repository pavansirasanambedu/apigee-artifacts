var responseJson = JSON.parse(context.getVariable("response.content"));
var statusCode = context.setVariable("statusCode","200");


if (statusCode !== null) {
    return statusCode;
    // console.log(statusCode);
}
else {
    return null;
    // console.log("null");
}