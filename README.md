# DNS Query Sender
A packet manipulator that sends queries to DNS servers to replicate a DNS query.
The goal of this project was to learn more about network protocols and to become more familiar with packet manipulation and cross-server communication.

# Structure
client.py is used to send the DNS query and decode responses while resolver.py contains the logic for the query. 

# Instructions 
Run client.py. The first argument given is the IP of the resolver, normally the local address. argument 2 is the port the resolver is listening on, argument 3 is the website name you want the IP of, and argument 4 is how long the client should wait for a response before timing out.
```
python3 client.py 127.0.0.1 53 google.com 500
```
In the above example, the resolver is being hosted locally, it is listening on port 53, we are sending a DNS query attempting to get the IP of google.com, and the client will wait for 500ms before timing out.
