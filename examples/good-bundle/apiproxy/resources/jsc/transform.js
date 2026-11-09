// Drop the provider's internal fields before the response goes out.
var body = JSON.parse(context.getVariable("response.content"));
delete body.internal;
context.setVariable("response.content", JSON.stringify(body));
