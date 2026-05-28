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

import casa.util.geom.CoordCar;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import casa.lepton.OppNet;
import casa.lepton.OppNodeListener;
import casa.lepton.OppEdgeListener;

/**
 * Class implementing the {@link casa.lepton.OppNet} methods by sending requests
 * to a {@link OppNetConsole} through a TCP session.
 *
 */
public class OppNetProxy implements OppNet {
    
    private static final String TAG = OppNetProxy.class.getName();
    private String host;
    private int port;
    private Socket socket; // socket connected to a {@link NetworkConsole}
    private BufferedReader reader; // socket's reader
    private BufferedWriter writer; // socket's writer
    private Map<String, ListenerThread> edgeListeners;
    private Map<String, ListenerThread> nodeListeners;

    /**
     * Opens a socket with the {@link OppNetConsole} waiting on the given
     * host/port
     *
     * @param host the name of the console host
     * @param port the console TCP port number
     * @throws IOException
     */
    public OppNetProxy(String host, int port) throws IOException {
        this.host = host;
        this.port = port;
        socket = new Socket(host, port);
        this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()), 256);
        this.writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()), 256);
        edgeListeners = new HashMap<>();
        nodeListeners = new HashMap<>();
    }

    /**
     * Close all opened resources.
     */
    public void close() {
        try {
            writer.write("quit\n");
        } catch (IOException e) {
            // DO NOTHING
        }
        try {
            reader.close();
        } catch (IOException e) {
            // DO NOTHING
        }
        try {
            writer.close();
        } catch (IOException e) {
            // DO NOTHING
        }
        try {
            socket.close();
        } catch (IOException e) {
            // DO NOTHING
        }
    }

    //----------------------------------------------------------------
    // Commands processing
    //----------------------------------------------------------------
    /*
     * Process a command by sending a request to the
     * {@link OppNetConsole} and returns its reply.
     */
    private synchronized String process(String[] args) {
        try {
            String request = toString(args);
            writer.write(request + "\n");
            writer.flush();
            String line = reader.readLine();
            if (line != null) {
                if (!line.startsWith("ERR ")) {
                    return removeDot(line);
                } else {
                    System.err.println("Error while processing \""
                            + request + "\": "
                            + line.substring(4));
                }
            }
        } catch (IOException e) {
            // DO NOTHING
            e.printStackTrace();
        }
        return null;
    }

    private String removeDot(String str) {
        if (str.endsWith(".")) {
            return str.substring(0, str.length() - 1);
        }
        return str;
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public void addNode(String nodeId, String profile) {
        if (profile == null) {
            process(new String[]{getTextCommand(OppNetCommand.addNode), nodeId});
        } else {
            process(new String[]{getTextCommand(OppNetCommand.addNode), nodeId, profile});
        }
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public void deleteNode(String nodeId) {
        process(new String[]{getTextCommand(OppNetCommand.deleteNode), nodeId});

    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isNode(String nodeId) {
        String reply = process(new String[]{getTextCommand(OppNetCommand.isNode), nodeId});
        return parseBoolean(reply);
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<String> getNodes() {
        String reply = process(new String[]{getTextCommand(OppNetCommand.getNodes)});
        return parseCollection(reply);
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public void setOnline(String nodeId, boolean online) {
        process(new String[]{getTextCommand(OppNetCommand.setOnline), nodeId, Boolean.toString(online)});
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isOnline(String nodeId) {
        String reply = process(new String[]{getTextCommand(OppNetCommand.isOnline), nodeId});
        return parseBoolean(reply);
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public void setTag(String nodeId, String tag) {
        process(new String[]{getTextCommand(OppNetCommand.setTag), nodeId, tag});
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public String getTag(String nodeId) {
        String reply = process(new String[]{getTextCommand(OppNetCommand.getTag), nodeId});
        return reply;
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public void addConnectivityType(String nodeId, String connectivityType) {
        process(new String[]{getTextCommand(OppNetCommand.addConnectivityType), nodeId, connectivityType});
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public void removeConnectivityType(String nodeId,
            String connectivityType) {
        process(new String[]{getTextCommand(OppNetCommand.removeConnectivityType), nodeId,
            connectivityType});
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public void setNodeStatus(String nodeId,
            String connectivityType, String status) {
        process(new String[]{getTextCommand(OppNetCommand.setNodeStatus), nodeId,
            connectivityType, status});
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public String getNodeStatus(String nodeId, String connectivityType) {
        String reply = process(new String[]{getTextCommand(OppNetCommand.getNodeStatus), nodeId,
            connectivityType});
        if ("null".equals(reply)) {
            reply = null;
        }
        return reply;
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean setEdgeStatus(String nodeId1, String nodeId2,
            String connectivityType, String status) {
        String reply = process(new String[]{getTextCommand(OppNetCommand.setEdgeStatus),
            nodeId1, nodeId2, connectivityType, status});
        return parseBoolean(reply);
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public String getEdgeStatus(String nodeId1, String nodeId2,
            String connectivityType) {
        String reply = process(new String[]{getTextCommand(OppNetCommand.getEdgeStatus),
            nodeId1, nodeId2, connectivityType});
        if ("null".equals(reply)) {
            reply = null;
        }
        return reply;
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<String> getNeighbors(String nodeId,
            String connectivityType, String edgeStatus) {
        String reply = process(new String[]{getTextCommand(OppNetCommand.getNeighbors),
            nodeId, connectivityType, edgeStatus});
        return parseCollection(reply);
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public int nbNeighbors(String nodeId,
			   String connectivityType, String edgeStatus) {
	Collection<String> neighbors = getNeighbors(nodeId, connectivityType,
						    edgeStatus);
	if (neighbors == null)
	    return 0;
	else
	    return neighbors.size();
    }
    
    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean areNeighbors(String nodeId1, String nodeId2,
            String connectivityType, String edgeStatus) {
        String reply = process(new String[]{getTextCommand(OppNetCommand.areNeighbors),
            nodeId1, nodeId2, connectivityType, edgeStatus});
        return parseBoolean(reply);
    }

    //-------------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public String makeEdgeId(String id1, String id2, String connectivityType) {
        String reply = process(new String[]{getTextCommand(OppNetCommand.makeEdgeId),
            id1, id2, connectivityType});
        if ("null".equals(reply)) {
            reply = null;
        }
        return reply;
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public void addEdgeListener(String nodeId,
            String connectivityType, OppEdgeListener listener) {
        addEdgeListener(nodeId, connectivityType, null, listener);
    }

    //----------------------------------------------------------------
    public void addEdgeListener(String nodeId,
            String connectivityType, String status, OppEdgeListener listener) {
        try {
            ListenerThread thread = new ListenerThread(host, port, listener);
            String key = nodeId + " " + connectivityType;
            if (status != null) {
                key += " " + status;
            }
            edgeListeners.put(key, thread);
            thread.write(getTextCommand(OppNetCommand.addEdgeListener) + " " + key);
            thread.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public void removeEdgeListener(String nodeId, String connectivityType) {
        removeEdgeListener(nodeId, connectivityType, null);
    }

    //----------------------------------------------------------------
    public void removeEdgeListener(String nodeId, String connectivityType, String status) {
        String key = nodeId + " " + connectivityType;
        if (status != null) {
            key += " " + status;
        }
        ListenerThread thread = edgeListeners.remove(key);
        if (thread != null) {
            try {
                thread.write(getTextCommand(OppNetCommand.removeEdgeListener) + " " + key);
            } catch (IOException e) {
                e.printStackTrace();
            }
            thread.close();
        }
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public void addNodeListener(String nodeId, OppNodeListener listener) {
        try {
            ListenerThread thread = new ListenerThread(host, port, listener);
            nodeListeners.put(nodeId, thread);
            thread.write(getTextCommand(OppNetCommand.addNodeListener) + " " + nodeId);
            thread.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //----------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public void removeNodeListener(String nodeId) {
        ListenerThread thread = nodeListeners.remove(nodeId);
        if (thread != null) {
            try {
                thread.write(getTextCommand(OppNetCommand.removeNodeListener) + " " + nodeId);
            } catch (IOException e) {
                e.printStackTrace();
            }
            thread.close();
        }
    }

    //----------------------------------------------------------------
    // Source/Sink processor
    //----------------------------------------------------------------
    private class ListenerThread extends Thread {

        private Socket socket;
        private BufferedReader reader;
        private BufferedWriter writer;
        private OppEdgeListener edgeListener;
        private OppNodeListener nodeListener;

        public ListenerThread(String host, int port, OppEdgeListener listener)
                throws IOException {
            this(host, port);
            this.edgeListener = listener;
        }

        public ListenerThread(String host, int port, OppNodeListener listener)
                throws IOException {
            this(host, port);
            this.nodeListener = listener;
        }

        private ListenerThread(String host, int port)
                throws IOException {
            socket = new Socket(host, port);
            this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream()), 256);
            this.writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()), 256);
        }

        public void write(String line) throws IOException {
            writer.write(line + "\n");
            writer.flush();
        }

        @Override
        public void run() {
            try {
                String line = reader.readLine();
                while (line != null) {
                    if (!line.equals("")) {
                        notify(line);
                    }
                    line = reader.readLine();
                }
            } catch (IOException e) {
                // DO NOTHING
            }
        }

        public void close() {
            try {
                reader.close();
            } catch (IOException e) {
                // DO NOTHING
            }
            try {
                writer.close();
            } catch (IOException e) {
                // DO NOTHING
            }
            try {
                socket.close();
            } catch (IOException e) {
                // DO NOTHING
            }
        }

        private synchronized void notify(String event) {
            String[] args = event.split("(\t| +)");
            if (args.length < 2) {
                return;
            }

            String command = args[0];
            switch (command) {
                case EDGE_ADDED:
                    if (args.length < 4) {
                        return;
                    }
                    edgeListener.edgeAdded(args[1], args[3]);
                    break;
                case EDGE_REMOVED:
                    if (args.length < 4) {
                        return;
                    }
                    edgeListener.edgeRemoved(args[1], args[3]);
                    break;
                case EDGE_CHANGED:
                    if (args.length < 4) {
                        return;
                    }
                    edgeListener.edgeChanged(args[1], args[3]);
                    break;
                case NODE_ADDED:
                    nodeListener.nodeAdded(args[1]);
                    break;
                case NODE_REMOVED:
                    nodeListener.nodeRemoved(args[1]);
                    break;
                case NODE_MOVED:
                    if (args.length < 3) {
                        return;
                    }
                    CoordCar coord = CoordCar.fromString(args[2]);
                    nodeListener.nodeMoved(args[1], coord);
                    break;
                default:
                    break;
            }
        }
    }

    //----------------------------------------------------------------
    // Private methods
    //----------------------------------------------------------------
    /*
     * Give a string composed of ' ' separated args. 
     */
    private String toString(String[] args) {
        if (args == null || args.length == 0) {
            return "";
        }
        if (args.length == 1) {
            return args[0];
        }
        StringBuffer buffer = new StringBuffer(args[0]);
        for (int i = 1; i < args.length; i++) {
            buffer.append(" " + args[i]);
        }
        return buffer.toString();
    }

    //----------------------------------------------------------------
    /*
     * Give a collection from its string representation.
     */
    private Collection<String> parseCollection(String line) {
        if (line == null || line.equals("null")) {
            return null;
        }

        if (line.startsWith("[")) {
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

    //----------------------------------------------------------------
    /*
     * Give a boolean from its string representation.
     */
    private boolean parseBoolean(String line) {
        if (line == null) {
            return false;
        }
        return Boolean.parseBoolean(line);
    }

    private String getTextCommand(OppNetCommand command) {
        return command.getAbbr();
//        return Integer.toString(command.ordinal());
    }
}
