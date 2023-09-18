// FL implemented -- Domain name, hostname, session path, siteId, region, cachedservices, 
var domain = context.setVariable("hostname", "34.36.127.68.nip.io");
var hostnameprefix = context.getVariable("(app.flapi.origin.generic)");  //defined in properties
var fullHostNamewithDomain = domain+hostnameprefix
sessionId = context.getVariable("session.id");
registerId = context.getVariable("register.id");
