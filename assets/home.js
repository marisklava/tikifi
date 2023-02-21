function Get(uri){
    var req = new XMLHttpRequest(); // a new request
    req.open("GET",uri,false);
    req.send(null);
    return req.responseText;          
}

events = Get("/events")
console.log(events)