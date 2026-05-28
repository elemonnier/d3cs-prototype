/* *****************************************************************************
 * Copyright (c) IRISA Laboratory,
 * Universite Bretagne Sud, France
 * <http://www-casa.irisa.fr/lepton>
 *
 * This file is part of LEPTON.
 *
 * LEPTON is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later
 * version.
 *
 * LEPTON is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Lepton.  If not, see <http://www.gnu.org/licenses/>.
 * ****************************************************************************/
package casa.lepton.console;

import casa.lepton.OppEdge;
import casa.lepton.OppNetGraph;
import casa.lepton.OppNode;
import casa.lepton.conf.OppNetProperties;
import casa.lepton.conf.NodeLabels;
import static casa.lepton.console.OppNetCommand.UNKNOWN;
import static casa.lepton.console.OppNetCommand.addConnectivityType;
import static casa.lepton.console.OppNetCommand.addNode;
import static casa.lepton.console.OppNetCommand.areNeighbors;
import static casa.lepton.console.OppNetCommand.addEdgeListener;
import static casa.lepton.console.OppNetCommand.addNodeListener;
import static casa.lepton.console.OppNetCommand.deleteNode;
import static casa.lepton.console.OppNetCommand.getEdgeStatus;
import static casa.lepton.console.OppNetCommand.getNeighbors;
import static casa.lepton.console.OppNetCommand.getNodeStatus;
import static casa.lepton.console.OppNetCommand.getNodes;
import static casa.lepton.console.OppNetCommand.getTag;
import static casa.lepton.console.OppNetCommand.isNode;
import static casa.lepton.console.OppNetCommand.isOnline;
import static casa.lepton.console.OppNetCommand.makeEdgeId;
import static casa.lepton.console.OppNetCommand.removeConnectivityType;
import static casa.lepton.console.OppNetCommand.removeEdgeListener;
import static casa.lepton.console.OppNetCommand.removeNodeListener;
import static casa.lepton.console.OppNetCommand.setEdgeStatus;
import static casa.lepton.console.OppNetCommand.setNodeStatus;
import static casa.lepton.console.OppNetCommand.setOnline;
import static casa.lepton.console.OppNetCommand.setTag;
import casa.util.channel.LineSocketChannel;
import casa.util.geom.CoordCar;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Class processing text commands sent through a TCP session by invoking the
 * methods of a {@link OppNetGraph} instance.
 */
public class OppNetConsole {

    private static final OppNetCommand[] CMDS = OppNetCommand.values();
    private static final String HELP = " "
            + addNode.ordinal() + ". add node:                 " + addNode.getAbbr() + " <nodeId> [<profile>]\n "
            + deleteNode.ordinal() + ". delete node:              " + deleteNode.getAbbr() + " <nodeId>\n "
            + isNode.ordinal() + ". is node:                  " + isNode.getAbbr() + " <nodeId>\n "
            + getNodes.ordinal() + ". get nodes:                " + getNodes.getAbbr() + "\n\n "
            + setOnline.ordinal() + ". set online:               " + setOnline.getAbbr() + " <nodeId> <online>\n "
            + isOnline.ordinal() + ". is online:                " + isOnline.getAbbr() + " <nodeId>\n "
            + setTag.ordinal() + ". set tag:                  " + setTag.getAbbr() + " <nodeId> <tag>\n "
            + getTag.ordinal() + ". get tag:                  " + getTag.getAbbr() + " <nodeId>\n\n "
            + addConnectivityType.ordinal() + ". add connectivity type:    " + addConnectivityType.getAbbr() + " <nodeId> <connectivityType>\n "
            + removeConnectivityType.ordinal() + ". remove connectivity type: " + removeConnectivityType.getAbbr() + " <nodeId> <connectivityType>\n\n "
            + setNodeStatus.ordinal() + ". set node status:         " + setNodeStatus.getAbbr() + " <nodeId> [<connectivityType>] <status>\n "
            + getNodeStatus.ordinal() + ". get node status:         " + getNodeStatus.getAbbr() + " <nodeId> [<connectivityType>]\n "
            + setEdgeStatus.ordinal() + ". set edge status:         " + setEdgeStatus.getAbbr() + " <nodeId1> <nodeId2> [<connectivityType>] <status>\n "
            + getEdgeStatus.ordinal() + ". get edge status:         " + getEdgeStatus.getAbbr() + " <nodeId1> <nodeId2> [<connectivityType>]\n\n "
            + getNeighbors.ordinal() + ". get neighbors:           " + getNeighbors.getAbbr() + " <nodeId> [<connectivityType> [<edgeStatus>]]\n "
            + areNeighbors.ordinal() + ". are neighbors:           " + areNeighbors.getAbbr() + " <nodeId1> <nodeId2> [<connectivityType> [<edgeStatus>]]\n\n "
            + makeEdgeId.ordinal() + ". make edge id:            " + makeEdgeId.getAbbr() + " <nodeId1> <nodeId2> [<connectivityType>]\n\n "
            + addEdgeListener.ordinal() + ". add edge listener:       " + addEdgeListener.getAbbr() + " <nodeId> [<connectivityType> [<edgeStatus>]]\n "
            + removeEdgeListener.ordinal() + ". remove edge listener:    " + removeEdgeListener.getAbbr() + " <nodeId> [<connectivityType> [<edgeStatus>]]\n "
            + addNodeListener.ordinal() + ". add node listener:       " + addNodeListener.getAbbr() + " <nodeId>\n "
            + removeNodeListener.ordinal() + ". remove node listener:    " + removeNodeListener.getAbbr() + " <nodeId>\n ";

    private final Thread consoleThread;
    private final Thread processorThread;
    private final Map<String, LineSocketChannel> edgeListeners;
    private final Map<String, LineSocketChannel> nodeListeners;
    private final NodeLabels labels;

    private final OppNetGraph oppNetGraph;
    private final BlockingQueue<Request> requests;

    private final String defaultConnectivityType;
    private final static int REQUEST_QUEUE_SIZE = 50;

    private boolean closed;
    private final Map<SelectionKey, LineSocketChannel> clientChannels;

    //----------------------------------------------------------------
    private class Request {

        String request;
        SelectionKey key;

        public Request(String request, SelectionKey key) {
            this.request = request;
            this.key = key;
        }
    }

    //----------------------------------------------------------------
    /**
     * Constructor.
     *
     * @param oppNetGraph the graph
     * @param props
     * @throws IOException
     */
    public OppNetConsole(OppNetGraph oppNetGraph, OppNetProperties props) throws IOException {
        this.requests = new LinkedBlockingQueue<>(REQUEST_QUEUE_SIZE);
        this.edgeListeners = new ConcurrentHashMap<>();
        this.nodeListeners = new ConcurrentHashMap<>();
        this.clientChannels = new ConcurrentHashMap<>();
        this.oppNetGraph = oppNetGraph;
        this.labels = props.getOppNodeProperties().getNodeLabels();
        this.defaultConnectivityType = props.getDefaultConnectivityType();
        this.consoleThread = makeConsoleThread(props.getConsolePort());
        this.processorThread = makeProcessorThread();
    }

    //----------------------------------------------------------------
    // Commands processing
    //----------------------------------------------------------------
    /*
     * Process a client command and returns a reply.
     * @param request method name and arguments.
     * @param client a reference to the client for the addListener command.
     * @return the reply returned by the command or ""
     */
    private String process(String request, LineSocketChannel client)
            throws Exception {
        String reply = null;
        String[] args = request.split("(\t| +)");

        System.out.println("[console] request: " + request);
        if (args.length < 1) {
            throw new Exception("Unknown command");
        }

        OppNetCommand command = getCommand(args[0]);
        switch (command) {
            case addNode:
                if (args.length == 2 || args.length == 3) {
                    String profile = (args.length == 3 ? args[2] : null);
                    oppNetGraph.addNode(getNodeId(args[1]), profile);
                    reply = "";
                }
                break;
            case deleteNode:
                if (args.length == 2) {
                    oppNetGraph.deleteNode(getNodeId(args[1]));
                    reply = "";
                }
                break;
            case isNode:
                if (args.length == 2) {
                    boolean ret = oppNetGraph.isNode(getNodeId(args[1]));
                    reply = Boolean.toString(ret);
                }
                break;
            case getNodes:
                if (args.length == 1) {
                    Collection<String> ret = oppNetGraph.getNodes();
                    reply = (ret == null ? "null" : ret.toString().replaceAll(" ", ""));
                }
                break;
            case setOnline:
                if (args.length == 3) {
                    oppNetGraph.setOnline(getNodeId(args[1]), Boolean.parseBoolean(args[2]));
                    reply = "";
                }
                break;
            case isOnline:
                if (args.length == 2) {
                    boolean ret = oppNetGraph.isOnline(getNodeId(args[1]));
                    reply = Boolean.toString(ret);
                }
                break;
            case setTag:
                if (args.length == 3) {
                    oppNetGraph.setTag(getNodeId(args[1]), args[2]);
                    reply = "";
                }
                break;
            case getTag:
                if (args.length == 2) {
                    String ret = oppNetGraph.getTag(getNodeId(args[1]));
                    reply = (ret == null ? "null" : ret);
                }
                break;
            case addConnectivityType:
                if (args.length == 3) {
                    oppNetGraph.addConnectivityType(getNodeId(args[1]), args[2]);
                    reply = "";
                }
                break;
            case removeConnectivityType:
                if (args.length == 3) {
                    oppNetGraph.removeConnectivityType(getNodeId(args[1]), args[2]);
                    reply = "";
                }
                break;
            case setNodeStatus: {
                if (args.length == 3 || args.length == 4) {
                    String type = (args.length == 4 ? args[2] : defaultConnectivityType);
                    String status = args[args.length - 1];
                    oppNetGraph.setNodeStatus(getNodeId(args[1]), type, status);
                    reply = "";
                }
                break;
            }
            case getNodeStatus: {
                if (args.length == 2 || args.length == 3) {
                    String type = (args.length == 3 ? args[2] : defaultConnectivityType);
                    String ret = oppNetGraph.getNodeStatus(getNodeId(args[1]), type);
                    reply = (ret == null ? "null" : ret);
                }
                break;
            }
            case setEdgeStatus: {
                if (args.length == 4 || args.length == 5) {
                    String type = (args.length == 5 ? args[3] : defaultConnectivityType);
                    String status = args[args.length - 1];
                    oppNetGraph.setEdgeStatus(getNodeId(args[1]), getNodeId(args[2]), type, status);
                    reply = "";
                }
                break;
            }
            case getEdgeStatus: {
                if (args.length == 3 || args.length == 4) {
                    String type = (args.length == 4 ? args[3] : defaultConnectivityType);
                    String ret = oppNetGraph.getEdgeStatus(getNodeId(args[1]), getNodeId(args[2]), type);
                    reply = (ret == null ? "null" : ret);
                }
                break;
            }
            case getNeighbors: {
                if (args.length >= 2 && args.length <= 4) {
                    String type = (args.length > 2 && !args[2].equals("null") ? args[2] : null);
                    String status = (args.length > 3 && !args[3].equals("null") ? args[3] : null);
                    Collection<OppNode> ret = oppNetGraph.getNeighborsNodes(getNodeId(args[1]), type, status);
                    reply = (ret == null ? "null" : nodesToString(ret));
                }
                break;
            }
            case areNeighbors: {
                if (args.length >= 3 && args.length <= 5) {
                    String type = (args.length > 2 && !args[2].equals("null") ? args[2] : null);
                    String status = (args.length > 3 && !args[3].equals("null") ? args[3] : null);
                    boolean ret = oppNetGraph.areNeighbors(getNodeId(args[1]), getNodeId(args[2]), type, status);
                    reply = Boolean.toString(ret);
                }
                break;
            }
            case makeEdgeId: {
                if (args.length == 3 || args.length == 4) {
                    String type = (args.length == 4 ? args[3] : defaultConnectivityType);
                    reply = oppNetGraph.makeEdgeId(getNodeId(args[1]), getNodeId(args[2]), type);
                }
                break;
            }
            case addEdgeListener:
                if (args.length >= 2 && args.length <= 4) {
                    String type = (args.length > 2 && !args[2].equals("null") ? args[2] : null);
                    String status = (args.length > 3 && !args[3].equals("null") ? args[3] : null);
                    addEdgeListener(getNodeId(args[1]), type, status, client);
                    reply = "";
                }
                break;
            case removeEdgeListener:
                if (args.length >= 2 && args.length <= 4) {
                    String type = (args.length > 2 && !args[2].equals("null") ? args[2] : null);
                    String status = (args.length > 3 && !args[3].equals("null") ? args[3] : null);
                    removeEdgeListener(getNodeId(args[1]), type, status);
                    reply = "";
                }
                break;
            case addNodeListener:
                if (args.length == 2) {
                    addNodeListener(getNodeId(args[1]), client);
                    reply = "";
                }
                break;
            case removeNodeListener:
                if (args.length == 2) {
                    removeNodeListener(getNodeId(args[1]));
                    reply = "";
                }
                break;
            default:
                reply = HELP;
        }

        if (reply == null) {
            throw new Exception("Unknown arguments");
        }
        return reply + ".";
    }

    //----------------------------------------------------------------
    // Start/stop
    //----------------------------------------------------------------
    /**
     * Opens a server socket on console's TCP port and start waiting for
     * clients' requests.
     */
    public void startConsole() {
        this.processorThread.start();
        this.consoleThread.start();
    }

    /**
     * Close the server socket.
     */
    public void closeConsole() {
        closed = true;
    }

    //----------------------------------------------------------------
    // Channels events reception
    //----------------------------------------------------------------
    private Thread makeConsoleThread(int port) {
        return new Thread() {
            @Override
            public void run() {
                try (ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
                        Selector selector = Selector.open()) {
                    serverSocketChannel.bind(new InetSocketAddress(port));
                    serverSocketChannel.configureBlocking(false);
                    serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);

                    while (!closed) {
                        selector.select();
                        Iterator<SelectionKey> keys = selector.selectedKeys().iterator();
                        while (keys.hasNext()) {

                            SelectionKey key = keys.next();
                            keys.remove();
                            if (key.isAcceptable()) {
                                accept(key, selector);
                            } else if (key.isReadable()) {
                                read(key);
                            }
                        }
                    }
                } catch (IOException ex) {

                }
            }
        };
    }

    private void accept(SelectionKey key, Selector selector) throws IOException {

        ServerSocketChannel serverSocketChannel = (ServerSocketChannel) key.channel();
        SocketChannel socketChannel = serverSocketChannel.accept();

        if (socketChannel != null) {
            socketChannel.configureBlocking(false);
            SelectionKey clientKey = socketChannel.register(selector, SelectionKey.OP_READ);
            clientChannels.put(clientKey, new LineSocketChannel(socketChannel));
        }
    }

    private void read(SelectionKey key) throws IOException {
        LineSocketChannel clientChannel = clientChannels.get(key);
        
        if (clientChannel != null) {
            String line = clientChannel.readLine();
            if (line != null) {
                try {
                    requests.put(new Request(line, key));
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }
            }
        }
    }

    //----------------------------------------------------------------
    // Channels events reception
    //----------------------------------------------------------------
    private Thread makeProcessorThread() {
        return new Thread() {
            @Override
            public void run() {
                try {
                    Request request = requests.take();
                    while (!closed && request != null) {
                        LineSocketChannel clientChannel = clientChannels.get(request.key);
                        try {
                            String reply = process(request.request, clientChannel);
                            clientChannel.writeLine(reply);
                        } catch (Exception e) {
                            e.printStackTrace();
                            try {
                                clientChannel.writeLine("ERR " + e.getMessage() + ".");
                            } catch (IOException ex) {
                                // DO NOTHING
                            }
                        }
                        request = requests.take();
                    }
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }

            }
        };
    }

    //----------------------------------------------------------------
    // Listener/Source methods
    //----------------------------------------------------------------
    /*
     * Add a thread client as listener for edge events.
     */
    private void addEdgeListener(String nodeId, String connectivityType, String status, LineSocketChannel client) {
        String key = nodeId + " " + connectivityType;
        if (status != null) {
            key += " " + status;
        }
        edgeListeners.put(key, client);
    }

    /**
     * Remove a thread client as listener for edge events.
     *
     * @param nodeId a node id
     * @param connectivityType a connectivity type
     */
    private void removeEdgeListener(String nodeId, String connectivityType, String status) {
        String key = nodeId + " " + connectivityType;
        if (status != null) {
            key += " " + status;
        }
        edgeListeners.remove(key);
    }

    /*
     * Add a thread client as listener for network events.
     */
    private void addNodeListener(String nodeId, LineSocketChannel client) {
        synchronized (nodeListeners) {
            nodeListeners.put(nodeId, client);
        }

    }

    /*
     * Remove a thread client as listener for network events.
     */
    private void removeNodeListener(String nodeId) {
        synchronized (nodeListeners) {
            nodeListeners.remove(nodeId);
        }

    }

    public void notifyNodeListeners(OppNode node, String command) {
        String nodeId = node.getId();
        CoordCar coord = node.getCoord();
        String coordstr = (coord != null ? coord.toString() : "");
        synchronized (nodeListeners) {
            LineSocketChannel client = nodeListeners.get(node.getId());
            writeLine(client, command + " " + nodeId + " " + coordstr);
        }
    }

    public synchronized void notifyEdgeListeners(OppEdge edge, String command) {
        String nodeId1 = edge.getSourceNode().getId();
        String nodeId2 = edge.getTargetNode().getId();
        String type = edge.getConnectivityType();
        String status = edge.getStatus();

        String[] keys1 = {nodeId1 + " " + type, nodeId1 + " " + type + " " + status};
        String[] keys2 = {nodeId2 + " " + type, nodeId2 + " " + type + " " + status};

        for (String key : keys1) {
            LineSocketChannel client = edgeListeners.get(key);
            notifyEdgeListener(client, nodeId2, nodeId1, type, status, command);
        }
        for (String key : keys2) {
            LineSocketChannel client = edgeListeners.get(key);
            notifyEdgeListener(client, nodeId1, nodeId2, type, status, command);
        }
    }

    private void notifyEdgeListener(LineSocketChannel client, String nodeId1, String nodeId2,
            String type, String edgeStatus, String command) {
        writeLine(client, command + " "
                + nodeId1 + " " + nodeId2 + " " + type + " " + edgeStatus);
    }

    //----------------------------------------------------------------
    // Private methods
    //----------------------------------------------------------------
    /*
     * Give a collection from its string representation.
     */
    private Collection<String> parseCollection(String line) {
        if (line == null || line.equals("null")) {
            return null;
        }

        if (line.startsWith("[") || line.startsWith("{")) {
            line = line.substring(1, line.length() - 1);
        }
        Set<String> set = new HashSet<String>();
        for (String elt : line.split(",")) {
            elt = elt.trim();
            if (!elt.equals("")) {
                set.add(elt);
            }
        }
        return set;
    }

    private String getNodeId(String label) {
        if (labels != null) {
            return labels.getNodeId(label);
        } else {
            return label;
        }
    }

    private String nodesToString(Collection<OppNode> nodes) {
        StringBuilder builder = new StringBuilder();
        Iterator<OppNode> it = nodes.iterator();
        while (it.hasNext()) {
            builder.append(it.next().getId());
            if (it.hasNext()) {
                builder.append(",");
            }
        }
        return builder.toString();
    }

    private OppNetCommand getCommand(String txt) {
        for (OppNetCommand cmd : CMDS) {
            if (txt.equals(cmd.getAbbr())) {
                return cmd;
            }
        }
        return UNKNOWN;
    }

    private void closeChannel(LineSocketChannel channel) {
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException ex) {
                // DO NOTHING
            }
        }
    }

    private void writeLine(LineSocketChannel channel, String line) {
        if (channel != null) {
            try {
                channel.writeLine(line);
            } catch (IOException ex) {
                System.err.println("Error while writing " + line);
                ex.printStackTrace();
            }
        }
    }
}
