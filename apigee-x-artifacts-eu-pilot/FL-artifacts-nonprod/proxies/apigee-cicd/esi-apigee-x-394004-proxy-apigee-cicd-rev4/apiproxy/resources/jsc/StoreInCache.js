var cacheName = "shared-cache-test";
var createdId = context.getVariable("session.id");
var responseData = context.getVariable("response.body");

var cache = context.getCache(cacheName);
cache.put(createdId, responseData, 3600); // Cache the data for 1 hour
