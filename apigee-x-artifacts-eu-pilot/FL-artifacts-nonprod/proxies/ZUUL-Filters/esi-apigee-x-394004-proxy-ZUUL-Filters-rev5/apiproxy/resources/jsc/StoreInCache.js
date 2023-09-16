var cacheName = "cache-data";
var createdId = context.getVariable("session.id");
var responseData = context.getVariable("response.body");
var cache = context.getCache(cacheName);
if (responseData !== null) {
    cache.put(createdId, responseData, 3600); // Cache the data for 1 hour
    context.setVariable("cachehit", true);
}
else {
    context.setVariable("cache-error", "data not stored in the cache");
}