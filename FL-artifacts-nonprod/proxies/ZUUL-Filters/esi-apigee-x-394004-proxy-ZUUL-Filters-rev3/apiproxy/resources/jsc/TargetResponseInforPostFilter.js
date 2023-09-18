var responseJson = JSON.parse(context.getVariable("response.content"));
var statusCode = JSON.parse(context.getVariable("response.status"));
print(statusCode);
if (Integer.valueof(statusCode)>299) {
    print(statusCode);
}
else {
    context.setVariable("zgw-response-service", "t"); // target
    context.setVariable("zgw-response-status", statusCode);
    context.setVariable("zgw-response-uri", requri);
    context.setVariable("zgw-response-error-code", "undefined");
    context.setVariable("zgw-response-error-message", "undefined");
    context.setVariable("zgw-response-error-type", "undefined");
    context.setVariable("zgw-response-error-reason", "undefined");
    context.setVariable("zgw-response-error-details", "undefined");
}

// Here added only the good status codes from targets and not for the zuul cache