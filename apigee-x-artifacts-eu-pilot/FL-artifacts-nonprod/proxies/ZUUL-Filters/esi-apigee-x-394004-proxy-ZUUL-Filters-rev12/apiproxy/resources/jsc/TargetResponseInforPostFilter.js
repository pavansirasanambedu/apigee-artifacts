var responseJson = JSON.parse(context.getVariable("response.content"));
statusCode = context.getVariable("statusCode");

try {
    
    if ((response.content) !== null) {
        if (Integer.valueof(statusCode)>299) { 
            
        }
        else { //execute for only good status codes from target
        context.setVariable("zgw-response-service", "t"); // target
        context.setVariable("zgw-response-status", statusCode);
        context.setVariable("zgw-response-uri", requri);
        context.setVariable("zgw-response-error-code", "undefined");
        context.setVariable("zgw-response-error-message", "undefined");
        context.setVariable("zgw-response-error-type", "undefined");
        context.setVariable("zgw-response-error-reason", "undefined");
        context.setVariable("zgw-response-error-details", "undefined");
    }
            
    }
    else { //execute for only zuul cache
        if (Integer.valueof(statusCode)>299) {
            
        }
         else { //execute only for cache good responses
        context.setVariable("zgw-response-service", "c"); // target
        context.setVariable("zgw-response-status", statusCode);
        context.setVariable("zgw-response-uri", requri);
        context.setVariable("zgw-response-error-code", "undefined");
        context.setVariable("zgw-response-error-message", "undefined");
        context.setVariable("zgw-response-error-type", "undefined");
        context.setVariable("zgw-response-error-reason", "undefined");
        context.setVariable("zgw-response-error-details", "undefined");
    }
    }
} catch (Exception) {
    
}

// need to write code for the datastream for the GZip
