var clientIp = "";
var trueClientIp = context.getVariable("request.header.True-Client-IP");
 
if(trueClientIp){
    clientIp =  trueClientIp;
    context.setVariable("this is akamai client ip", clientIp);
} else{
    clientIp = context.getVariable("client.ip");
}

//value in the last octet
var lastOctetValue = clientIp.split(".")[3];
//index of last occurance of last octet
var lastOccurance = clientIp.lastIndexOf(lastOctetValue);
//first three octets
clientIp = clientIp.slice(0, lastOccurance);
// mask the last octet
clientIp += "*";
context.setVariable("clientIp", clientIp);

