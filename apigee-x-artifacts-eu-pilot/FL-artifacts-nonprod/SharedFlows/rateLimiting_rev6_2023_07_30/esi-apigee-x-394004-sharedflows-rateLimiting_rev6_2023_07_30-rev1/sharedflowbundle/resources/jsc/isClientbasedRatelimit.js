var isClientBasedRateLimit = context.getVariable("isClientBasedRatelimit");
var basepathList = context.getVariable("basePathList");

//basePath of current proxy
var myBasicPath = context.getVariable("proxy.basepath");

var isExactPathFound = isExactPathFound(myBasicPath);

//if client based rate limit is enabled and base path for that proxy exist in list
var isClientBasedRateLimitEnabled = (isClientBasedRateLimit === "true") && isExactPathFound;


context.setVariable("isClientBasedRateLimitEnabled", isClientBasedRateLimitEnabled);


//override only if Client Based RateLimit is Enabled for client and its owner
if(isClientBasedRateLimitEnabled){
    //this var is set in pouplateAppVariables sharedflow
    var client = context.getVariable("clientName");
    client= client.toLowerCase();
    
    
    //Backend based on basepath for Ex: cc for customer-core proxy  
    var owner = getOwner(myBasicPath);
    //zendesk_cc_
    var prefix = client + "_" + owner + "_"; 
    
    //override of ratelimiting variables based on client
    var spikeArrestEnabled = context.getVariable(prefix + "spikeArrestEnabled");
    var spikeArrestRate = context.getVariable(prefix + "spikeArrestRate");
    var spikeEffectiveCountIp = context.getVariable(prefix + "spikeEffectiveCountIp");
    
    context.setVariable("prefix", prefix);
    context.setVariable("spikeArrestEnabled", spikeArrestEnabled);
    context.setVariable("spikeArrestRate", spikeArrestRate);
    context.setVariable("spikeEffectiveCountIp", spikeEffectiveCountIp);

    
}



function isExactPathFound(myBasicPath){
    var isFound = false;
    var myArray = basepathList.split(",");
    for each(var element in myArray){
        /*looking for exact match*/
        if(element === myBasicPath){
          isFound = true;
          break;
        }
    }
    return isFound;
}

function getOwner(myBasicPath){
    
    var result = "undefined";

    if(myBasicPath.toLowerCase().includes("/api/v1/customer-core/customers")){
        result = "cc";
    }
    if(myBasicPath.toLowerCase().includes("/api/v2/oms")){
        result = "oms";
    }
    if(myBasicPath.toLowerCase().includes("/api/search-core/products/")){
        result = "search";
    }
    if(myBasicPath.toLowerCase().includes("/api/product-core/")){
        result = "product";
    }
    if(myBasicPath.toLowerCase().includes("/api/stores-core/")){
        result = "store";
    }
    
    return result;
}




