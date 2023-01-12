function Get(uri){
    var req = new XMLHttpRequest(); // a new request
    req.open("GET",uri,false);
    req.send(null);
    return req.responseText;          
}

events = Get("http://127.0.0.1:8000/events")
console.log(events)