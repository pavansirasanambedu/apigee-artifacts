var cacheName = "cache-data";
var responseJson = JSON.parse(context.getVariable("response.content"));
var cachekey = context.getVariable("session.id");
var statusCode = context.setVariable("statusCode","200");
var createdId = context.getVariable("session.id");
var responseData = context.getVariable("response.body");
// var cache = context.getCache(cacheName);

if (responseData !== null) {
    cache.put(createdId, responseData, 3600); // Cache the data for 1 hour
    context.setVariable("cachehit", true);
    responseJson.statuscode = statusCode;
    responseJson.cachekey = cachekey; // get Cache key as a string
    context.setVariable("response.content",JSON.stringify(responseJson));
    context.setVariable("request.header.cachekey", "session.id");
}
else {
    context.setVariable("cache-error", "data not stored in the cache");
}