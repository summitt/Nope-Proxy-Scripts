### Nope Server
The Nope extension uses Jython to execute python code. This works well in many instances but there are many limitations with jython. For example importing libraries is difficult and using Python3 is not possible in Jython. 

To over come this you can use this server and the nope_client.py as a starting place to write you own custom decoders and packet logging. 

#### Setup
1. Load nope_client.py by navigating to Automation and select Import Python in the Nope Proxy. 
2. Start the `python server.py`.

This is a simple echo server that will send any data passing through nope over to the server and then send it back un-altered. 
