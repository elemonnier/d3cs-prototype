
# DoDWAN Network API

The DoDWAN Network API (DoDWAN NAPI) has been added to DoDWAN so that DoDWAN
can be be used by an external piece of software, via a network protocol such as
TCP or WebSocket. When using WebSocket for example, this offers the possibility to
control DoDWAN from a web browser.

The external application acts then as a client of DoDWAN which can plays the
role of a network server thanks to its NAPI plugin.

In order to develop the client-side of your application, you should implement a
client of the [NAPI protocol](dodwan_network_api_protocol.html).  To ease this
task, a few libraries are available.



# Installing the Dodwan Network API plugin

Install this plugin like any other DoDWAN plugin: unzip the plugin ZIP archive
in the `$DODWAN_HOME/plugins` directory.



# Running the Dodwan Network API plugin

This plugin does nothing by itself. You should install another plugin (e.g. the
Dodwan Websocket Network API plugin) to actually benefit from a usable network API.

When launching DoDWAN, you should put in the shell variable `dodwan_plugins`
the short name of the Dodwan Network API plugin, followed by the actual network
Network API plugin name.

For example, the following command starts DoDWAN with the Websocket Network API
plugin (dodwan-napi-ws), and its dependency, the Network API plugin
(dodwan-napi):

    dodwan_plugins=dodwan-napi,dodwan-napi-ws  dodwan.sh start 



# Using a NAPI client library

A dedicated library is available for each implementation of the NAPI protocol.


## Java NAPI TCP client library

The Java library is available as a Maven dependency from the CASA repository:

    <!-- http://casa-irisa.univ-ubs.fr/download/maven2 -->
    <dependency>
        <groupId>casa.util</groupId>
        <artifactId>napi-tcp-client</artifactId>
        <version>1.0</version>
    </dependency>
    
### Usage

The Java NAPI client API comes with a default configuration, that can be
overwritten by providing custom properties (see the list of properties in the `casa.util.dodwanclient.Configuration` class).

    // configuring the NAPI TCP Client 
    Properties properties = new Properties();
    properties.put("server_host", "localhost");
    properties.put("server_port", 8030);
    properties.put("name", "default");          // the endpoint name
    Configuration.init(properties);
	
Before using the client services, a session must be started in order to open a TCP connection with the NAPI TCP server:

    Session session = Session.getInstance();
    
    // registering a listener to be notified when the session is ready
    session.addListener(new SessionListener() {
        @Override
        public void onSessionStarted()
        {
            // the session is ready 
        }
        // ... other SessionListener methods
    });
    
    // opening the connection with the NAPI server
    session.start();
    
When the session is ready, the `PeerService` and the `PubSubService` can be used. For example, to subscribe in order to receive messages pertaining to the `casa` group:

    PubSubService pubSub = PubSubService.getInstance();

    // describe the content type to subscribe to
    Descriptor desc = new Descriptor();
    desc.setAttribute("group", "casa");
	
	// add a subscription
    pubSub.addSubscription("key1", desc, new Processor<Descriptor>()
    {
        @Override
        public void process(Descriptor value) throws Exception
        {
            // a new message has been received. Retrieve the message content
            byte[] buffer = pubSub.getAsBuffer(value.getMid());
            // ... process the message content
        }
    });


## JavaScript NAPI Websocket client library

The Javascript library is available as a compressed tarball:
[casa-napi-ws-client-1.0.0.tgz](http://casa-irisa.univ-ubs.fr/download/nodejs/casa-napi-ws-client-1.0.0.tgz).

You may use it by adding a dependency in your package.json file:

    dependencies": {
        "@casa/napi-ws-client": "http://casa-irisa.univ-ubs.fr/download/nodejs/casa-napi-ws-client-1.0.0.tgz"
    }

