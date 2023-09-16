var responseJson = JSON.parse(context.getVariable("response.content"));
var statusCode = JSON.parse(context.getVariable("response.status"));


if (statusCode !== null) {
    console.log(statusCode);
}
else {
    console.log("null");
}