var responseJson = JSON.parse(context.getVariable("response.content"));
var statusCode = context.setVariable("statusCode","200");


if (statusCode !== null) {
    // console.log(statusCode);
}
else {
    // console.log("null");
}