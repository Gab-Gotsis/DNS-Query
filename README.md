The client is used to send the DNS query and decode responses, resolver contains the logic for the query. To run, run client.py. Arg 1 is the resolver_ip, Arg 2 is the resolver port, Arg 3 is the website name you want the IP of, Arg 4 is how long the client should wait for a response before timing out.

For example: client.py 127.0.0.1 53 google.com 500
