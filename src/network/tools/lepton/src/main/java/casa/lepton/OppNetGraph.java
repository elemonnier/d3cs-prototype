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
package casa.lepton;

import casa.dgs.DGSAttributes;
import casa.lepton.conf.ConnectivityProfiles;
import casa.lepton.conf.OppNetProperties;
import casa.lepton.conf.OppNodeProperties;
import casa.lepton.console.OppNetConsole;
import casa.lepton.hub.Hub;
import casa.lepton.ui.OppNetFrame;
import casa.lepton.ui.OppNetOutput;
import casa.lepton.walk.Walk;
import casa.util.geom.AreaCar;
import casa.util.geom.CoordCar;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentHashMap;
import org.graphstream.algorithm.Toolkit;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.graphstream.graph.implementations.MultiGraph;

/**
 * A {@link OppNetGraph} represents a network composed of devices
 * ({@link OppNode}) linked by edges ({@link OppEdge}) representing actual or
 * possible connections between them.
 *
 * Multiple edges can exist between two nodes, each edge representing a
 * connection between the nodes through a specific connectivity type
 * ({@link OppEdge#getConnectivityType()}), provided both nodes support the
 * connectivity type ({@link OppNode#hasConnectivityType(String)}).
 *
 * The graph is dynamic: it is runnable ({@link #play()} and {@link #stop()}
 * methods). At each step, its nodes move and edges are updated accordingly:
 * edges are added (resp. removed) if the nodes are (resp. no more) in mutual
 * radio range according to their connectivity types
 * ({@link OppNetGraph#areInRange(OppNode, OppNode, String)}).
 *
 * The steps are characterized by a simulation time. The simulation can run in
 * real time or not (accelerated or slowed down).
 *
 * This class has two main subclasses: {@link OppNetGraphDGS} if the simulation
 * is run according to an input DGS file and {@link OppNetGraphWalk} if the
 * simulation is run according to a mobility model (see {@link Walk}).
 *
 */
public class OppNetGraph extends MultiGraph implements OppNet, Runnable, Closeable {

    protected final OppNetProperties props;

    protected final PrintWriter dgsWriter; // output stream to a DGS file to log the simulation (can be null)
    protected long lastLogTime;            // the last simulation time already logged in the DGS output (see {@link #logDGS(String)})

    protected final long duration;         // duration of the simulation (in ms)
    protected final long period;           // period (in ms) between steps for {@link #run()}

    protected final boolean makeEdges;     // true if the edges must be calculated

    protected long currentStep;            // the current step of the simulation
    protected long refTime;                // the time at the beginning of the simulation
    private double accel;                  // the simulation acceleration (see {@link NetworkGraphProperties#getAccel()})
    private double newAccel;               // the simulation acceleration for the next step
    protected TimeZone timezone;           // the timezone of the step times (null: system local timezone)

    // the real time, used as reference to compute the wait time at each step. Its value is
    // the time that would be given by {@link System#currentTimeMillis()} at currentStep=0
    // provided the accel value has not changed since the beginning.
    private long startTime;
    private long stopTime;                  // the real time when the simulation was stopped through the stop() method

    protected boolean started;                            // true if the simulation is currently playing
    protected Thread thread;                              // currently running thread, initialized in the {@link play()} method
    protected boolean hasNext = true;                     // true if the simulation has more steps to run

    protected AreaCar area;                               // the graph area
    protected OppNetRules oppNetRules;                    // rules attached to this graph
    protected ConnectivityProfiles connectivityProfiles;  // the profiles of connectivity types
    protected String defaultConnectivityType;             // the default connectivity type

    protected OppNodeFactory nodeFactory;                 // used to create nodes
    protected OppEdgeFactory edgeFactory;                 // used to create edges

    protected OppNetConsole console;                      // a console used to access the graph
    protected Hub hub;                                    // the hub that allows emulated nodes to communicate with each others
    protected Map<String, OppEdgeListener> edgeListeners; // listeners for edge events
    protected Map<String, OppNodeListener> nodeListeners; // listeners for node events

    protected OppNetFrame frame;                          // the frame to display the simulation (may be null)
    protected OppNetOutput output;                        // the output to produce a video

    // events that will be played during the simulation generated from the nodes history
    private List<OppNetGraphWalk.NodeEvent> nodesEvents;  // an & dn events in chronological order
    private int nextEventIdx;                             // the index of the next event to be played

    protected final DGSAttributes graphAttributes;

    private final Map<String, double[]> positions;        // last nodes positions. Used by the {@link hasMoved()} method

    //-------------------------------------------------------------------------
    /**
     * Graph attributes initialization from the given properties.
     *
     * @param networkId the graph id
     * @param props the graph properties
     * @throws IOException if an error occurs while opening the console
     */
    protected OppNetGraph(String networkId, OppNetProperties props) throws IOException {

        super(networkId, false, true);
        setStrict(false);   // disable strict checking ({@link Graph#isStrict()})
        this.props = props;
        this.graphAttributes = new DGSAttributes(this);

        // logging
        this.dgsWriter = props.getDgsWriter();
        this.lastLogTime = -1;

        // simulation time
        this.refTime = props.getRefTime();
        this.accel = props.getAccel();
        this.newAccel = accel;
        this.period = props.getPeriod();
        this.duration = props.getDuration();

        this.makeEdges = props.makeEdges();
        this.positions = new HashMap<>();

        // TODO add timezone in the properties
        this.startTime = props.getLeptonStartTime();

        // write dgs header
        if (dgsWriter != null) {
            println(dgsWriter, "DGS004\n" + networkId + " 0 0");
        }

        // graph attributes
        this.oppNetRules = props.getOppNetRules();
        this.connectivityProfiles = props.getConnectivityProfiles();
        this.defaultConnectivityType = props.getDefaultConnectivityType();

        // node & edge factories
        OppNodeProperties nodeProperties = props.getOppNodeProperties();
        this.nodeFactory = new OppNodeFactory(nodeProperties);
        this.setNodeFactory(nodeFactory);
        this.edgeFactory = new OppEdgeFactory(props);
        this.setEdgeFactory(edgeFactory);

        // node & edge listeners
        if (props.getConsolePort() > 0) {
            this.console = new OppNetConsole(this, props);
        }

        // hub
        if (props.getHubPort() > 0 && props.getOppNetAdapter() != null) {
            try {
                this.hub = new Hub(this, props);
            } catch (Exception ex) {
                System.err.println("Unable to start the LEPTON hub: " + ex.getClass().getName() + " " + ex.getMessage());
                ex.printStackTrace();
            }
        }
        edgeListeners = new ConcurrentHashMap<>();
        nodeListeners = new ConcurrentHashMap<>();

        // nodes history: an & dn events
        String nodesHist = props.getNodesHist();
        if (nodesHist != null) {
            nodesEvents = makeEvents(nodesHist);
        }

        // ui
        String css = props.getStylesheet();
        if (css != null) {
            setAttribute("ui.stylesheet", css);
        }

        setArea(props.getSimulArea());
    }

    //-------------------------------------------------------------------------
    // Getters & setters
    //-------------------------------------------------------------------------
    public DGSAttributes getAttributes() {
        return graphAttributes;
    }

    /**
     * Return true if a console is provided to access the graph
     *
     * @return true if there is a console
     */
    public boolean hasConsole() {
        return console != null;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the console
     *
     * @return the console
     */
    public OppNetConsole getConsole() {
        return console;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the hub
     *
     * @return the hub
     */
    public Hub getHub() {
        return hub;
    }

    //-------------------------------------------------------------------------
    /**
     * Make a unique instance of the frame that displays the graph if
     * {@link OppNetProperties#isShow()} is true
     *
     * @return the frame
     */
    public OppNetFrame makeFrame() {

        if (frame == null && props.isShow()) {
            frame = new OppNetFrame(this, props);
        }

        return frame;
    }

    //-------------------------------------------------------------------------
    /**
     * Make a unique instance of {@link OppNetOutput}, that produces a video of
     * the simulation if {@link OppNetProperties#getVideoImgDir()} is not null
     *
     * @return {@link OppNetOutput} instance
     */
    public OppNetOutput makeOutput() {

        if (output == null && props.getVideoImgDir() != null) {
            output = new OppNetOutput(this, props);
        }

        return output;
    }

    //-------------------------------------------------------------------------
    /**
     * Give a unique edge id from the given nodes ids and connectivityType in
     * the form "idA-idB:type" where idA = min(id1,id2) and idB = max(id1,id2).
     *
     * @param id1 a node id.
     * @param id2 other node id.
     * @param connectivityType the connectivity type.
     * @return unique edge id.
     */
    @Override
    public String makeEdgeId(String id1, String id2, String connectivityType) {
        return edgeFactory.makeEdgeId(id1, id2, connectivityType);
    }

    /**
     * Give the timezone of the step times
     *
     * @return the timezone
     */
    public TimeZone getTimeZone() {
        return this.timezone;
    }

    //-------------------------------------------------------------------------
    // Graph area
    //-------------------------------------------------------------------------
    /**
     * Give the graph area.
     *
     * @return the graph area
     */
    public AreaCar getArea() {
        return area;
    }

    //-------------------------------------------------------------------------
    /**
     * Set the graph area.
     *
     * @param area the new graph area (may be null)
     */
    public final void setArea(AreaCar area) {

        if (area != null) {

            if (this.area == null || !area.equals(this.area)) {
                setAttribute("area", area.toString());
                println(dgsWriter, "cg " + graphAttributes.toString("area"));
            }
        } else if (this.area != null) { // remove previous attributes

            removeAttribute("area");
            println(dgsWriter, "cg -area");
        }

        this.area = area;
    }

    //-------------------------------------------------------------------------
    // Graph evolution: steps
    //-------------------------------------------------------------------------
    /**
     * Starts playing the simulation.
     *
     */
    public synchronized void play() {
        if (!started) {

            started = true;

            if (stopTime > 0) {  // resume after a pause period
                startTime += System.currentTimeMillis() - stopTime;
                stopTime = 0;
            }

            thread = new Thread(this);
            thread.start();

        }
    }

    //-------------------------------------------------------------------------
    /**
     * Stops playing the simulation.
     *
     */
    public synchronized void stop() {
        if (started) {
            started = false;
            stopTime = System.currentTimeMillis();
        }
    }

    //-------------------------------------------------------------------------
    /**
     * Waits until the simulation is stopped.
     *
     */
    public synchronized void join() {
        if (started && thread != null) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                // DO NOTHING
            }
        }
    }

    //-------------------------------------------------------------------------
    /**
     * Stops playing the simulation and close all resources.
     *
     */
    @Override
    public synchronized void close() {
        System.out.println("Closing simulation. Frame: " + (this.frame != null && this.frame.isVisible()));
        stop();
        if (dgsWriter != null) {
            dgsWriter.close();
        }
        if (console != null) {
            console.closeConsole();
        }
        if (this.frame == null || !this.frame.isVisible()) {
            // TODO stop emulated nodes (?)
            File pidFile = new File(props.getLogDirectory(), "lepton-pid");
            if (pidFile.exists()) {
                pidFile.delete();
            }
            System.exit(0);
        }
    }

    //-------------------------------------------------------------------------
    /**
     * Run simulation steps separated by the period given at object's
     * instanciation.
     *
     */
    @Override
    public void run() {

        waitUntil(currentStep);

        while (started) {

            try {

                // make the an and dn events (generated from the history) for this step
                if (nodesEvents != null) {
                    while (nextEventIdx < nodesEvents.size() && nodesEvents.get(nextEventIdx).step <= currentStep) {
                        nodesEvents.get(nextEventIdx++).doEvent();
                    }
                }

                // run the next step
                this.hasNext = step();

                if (frame != null) {
                    frame.pump(); // allows the viewer to catch mouse events
                    if (!hasNext) {
                        frame.end();
                    }
                }
                if (dgsWriter != null) {
                    dgsWriter.flush();
                }
                started = started && hasNext;

            } catch (Throwable t) {
                t.printStackTrace();
            }
        }
        if (dgsWriter != null) {
            dgsWriter.flush();
        }
        if (!hasNext) {
            close();
        }
    }

    //-------------------------------------------------------------------------
    /**
     * Wait until the given step, with the <code>accel</code> factor.
     *
     * @param step the next step
     */
    protected void waitUntil(long step) {

//        System.out.println("   wait until " + step);
        long now = System.currentTimeMillis();

        // check whether the acceleration has changed
        if (newAccel != accel) {
            if (accel == 0) {
                this.startTime = now;
            }
            if (newAccel != 0) {
                // reset the ref time as if this acceleration had this value since the beginning
                this.startTime = now - Math.round(currentStep / newAccel);
            }
            this.accel = newAccel;
        }

        if (accel != 0) {
            long nextRealTime = startTime + Math.round(step / accel);
            long wait = nextRealTime - now;
            if (wait > 0) {
                try {
                    Thread.sleep(wait);
                } catch (Exception e) {
                }
            }
        }
        currentStep = step;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the simulation current acceleration
     *
     * @return the acceleration
     */
    public double getAccel() {
        return accel;
    }

    //-------------------------------------------------------------------------
    /**
     * Change the acceleration and reset the startTime accordingly. The
     *
     * @param newAccel the new acceleration
     */
    public void setAccel(double newAccel) {
        this.newAccel = newAccel;
    }

    //-------------------------------------------------------------------------
    /**
     * Run a simulation step: move nodes and update edges accordingly, and wait
     * for the next step time
     *
     * @return false if this step is the last one
     */
    public boolean step() {

        if ((duration > 0) && (currentStep > duration)) // the simulation duration is reached: stop simulation
        {
            return false;
        }

//        System.out.println("Step " + currentStep);
        super.stepBegins(currentStep);

        waitUntil(currentStep + period);

        if (this.makeEdges) {
            updateEdges();
        }

        return true;
    }

    //-------------------------------------------------------------------------
    /**
     * Gives the current step.
     */
    public long getCurrentStep() {
        return currentStep;
    }

    //-------------------------------------------------------------------------
    /**
     * Gives the current simulation time, extrapolated according to the real
     * time and the real start time, if the simulation is running. Else return
     * the time of the current step (currentStep + refTime)
     */
    public long getCurrentTime() {
        if (started && accel > 0) {
            long now = System.currentTimeMillis();
            return Math.round((now - startTime) * accel) + refTime;
        }
        return currentStep + refTime;
    }

    public long getRefTime() {
        return refTime;
    }

    /**
     * Return true if the simulation has more steps to run
     *
     * @return true if the simulation has more steps to run
     */
    public boolean hasNext() {
        return this.hasNext;
    }

    //-------------------------------------------------------------------------
    // Edges generation from radio ranges
    //-------------------------------------------------------------------------
    private void updateEdges() {
        Collection<OppNode> movedNodes = new HashSet<>();
        for (Node node : getNodeSet()) {
            OppNode oppNode = (OppNode) node;
            if (hasMoved(oppNode)) {
                movedNodes.add(oppNode);
            }
        }
        updateEdges(movedNodes);
    }

    protected void updateEdges(Collection<OppNode> movedNodes) {

        for (int i = 0; i < getNodeCount(); i++) {
            OppNode node = getNode(i);
            if (!node.isOnline()) {
                // remove all edges for offline nodes
                removeAllEdges(node);

            } else if (movedNodes.contains(node)) {

                // compute edges for moved nodes
                for (String type : node.getConnectivityTypes()) {
                    edgeFactory.setConnectivityType(type);

                    for (int j = 0; j < getNodeCount(); j++) {
                        OppNode node2 = getNode(j);
                        if (i != j && node2.isOnline()) {
                            String edgeId = edgeFactory.makeEdgeId(node, node2, type);
                            OppEdge edge = getEdge(edgeId);
                            boolean inRange = areInRange(node, node2, type);
                            if (edge == null && inRange) {
                                addEdge(edgeId, node, node2);
                            } else if (edge != null && !inRange) {
                                removeEdge(edge);
                            }
                        }
                    }
                }
            }
        }
    }

    //---------------------------------------------------------------
    private boolean hasMoved(OppNode node) {
        String id = node.getId();
        double[] prev = positions.get(id);
        double[] position = Toolkit.nodePosition(node);
        if (position != null && position.length > 1) {
            if (prev != null && prev[0] == position[0] && prev[1] == position[1]) {
                return false;
            }
            node.setCoord(new CoordCar(position[0], position[1]));
            positions.put(id, position);
            return true;
        }
        return false;
    }

    //-------------------------------------------------------------------------
    // Nodes
    //-------------------------------------------------------------------------
    @Override
    public synchronized void addNode(String nodeId, String profile) {
        // extract the profile from the nodeId
        if (getNode(nodeId) != null) {
            return;
        }
        nodeFactory.setProfile(profile);
        OppNode node = super.addNode(nodeId);
        if (node != null) {
            node.init();
            notifyNodeListeners(node, NODE_ADDED);
            logDGS("an " + node.toDGS());
        }
    }

    //-------------------------------------------------------------------------
    @Override
    public synchronized void deleteNode(String nodeId) {
        // remove the profile from the nodeId
        int sepIdx = nodeId.indexOf(":");
        if (sepIdx > 0 && sepIdx < nodeId.length() - 1) {
            nodeId = nodeId.substring(0, sepIdx);
        }
        OppNode node = super.removeNode(nodeId);
        if (node != null) {
            notifyNodeListeners(node, NODE_REMOVED);
            logDGS("dn " + nodeId);
        }
    }

    //-------------------------------------------------------------------------
    @Override
    public boolean isNode(String nodeId) {
        return super.getNode(nodeId) != null;
    }

    //-------------------------------------------------------------------------
    @Override
    public Set<String> getNodes() {
        Set<String> nodes = new HashSet<>();
        for (Node node : getNodeSet()) {
            nodes.add(node.getId());
        }
        return nodes;
    }

    //-------------------------------------------------------------------------
    @Override
    public synchronized void setOnline(String nodeId, boolean online) {
        OppNode node = getNode(nodeId);
        if (node != null) {
            setOnline(node, online);
        }
    }

    //-------------------------------------------------------------------------
    private void setOnline(OppNode node, boolean online) {
        boolean changed = node.setOnline(online);
        if (changed) {
            if (online) {
                resetEdges(node);
            } else {
                removeAllEdges(node);
            }
        }
    }

    //-------------------------------------------------------------------------
    @Override
    public boolean isOnline(String nodeId) {
        OppNode node = getNode(nodeId);
        if (node != null) {
            return node.isOnline();
        }
        return false;
    }

    //-------------------------------------------------------------------------
    @Override
    public synchronized void setTag(String nodeId, String tag) {
        OppNode node = getNode(nodeId);
        if (node != null) {
            String nodeTag = node.getTag();
            if (tag != null) {
                if (!tag.equals(nodeTag)) {
                    node.setTag(tag);
                    logDGS("cn " + node.toDGS());
                }
            } else if (nodeTag != null) {
                node.setTag(tag);
                logDGS("cn " + node.toDGS());
            }
        }
    }

    //-------------------------------------------------------------------------
    @Override
    public String getTag(String nodeId) {
        OppNode node = getNode(nodeId);
        if (node != null) {
            return node.getTag();
        }
        return null;
    }

    //-------------------------------------------------------------------------
    @Override
    public synchronized void addConnectivityType(String nodeId, String connectivityType) {
        OppNode node = getNode(nodeId);
        if (node != null) {
            addConnectivityType(node, connectivityType);
        }
    }

    //-------------------------------------------------------------------------
    private void addConnectivityType(OppNode node,
            String connectivityType) {
        boolean changed = node.addConnectivityType(connectivityType);
        if (changed) {
            resetEdges(node, connectivityType);
        }
    }

    //-------------------------------------------------------------------------
    @Override
    public synchronized void removeConnectivityType(String nodeId, String connectivityType) {
        OppNode node = getNode(nodeId);
        if (node != null) {
            removeConnectivityType(node, connectivityType);
        }
    }

    //-------------------------------------------------------------------------
    private void removeConnectivityType(OppNode node,
            String connectivityType) {
        boolean changed = node.removeConnectivityType(connectivityType);
        if (changed) {
            removeEdges(node, connectivityType);
        }
    }

    //-------------------------------------------------------------------------
    @Override
    public synchronized void setNodeStatus(String nodeId,
            String connectivityType, String status) {
        OppNode node = getNode(nodeId);
        if (node != null) {
            setNodeStatus(node, connectivityType, status);
        }
    }

    //-------------------------------------------------------------------------
    private void setNodeStatus(OppNode node,
            String connectivityType,
            String status) {
        boolean changed = node.setStatus(connectivityType, status);
        if (changed) {
            logDGS("cn " + node.toDGS());
        }

    }

    //-------------------------------------------------------------------------
    @Override
    public String getNodeStatus(String nodeId, String connectivityType) {
        OppNode node = getNode(nodeId);
        if (node != null) {
            return node.getStatus(connectivityType);
        }
        return null;
    }

    //----------------------------------------------------------------
    // Connectivity
    //-------------------------------------------------------------------------
    @Override
    public synchronized boolean setEdgeStatus(String nodeId1, String nodeId2,
            String connectivityType, String status) {
        String edgeId = edgeFactory.makeEdgeId(nodeId1, nodeId2,
                connectivityType);
        OppEdge edge = getEdge(edgeId);
        if (edge != null) {
            return setEdgeStatus(edge, status);
        }
        return false;
    }

    //-------------------------------------------------------------------------
    private boolean setEdgeStatus(OppEdge edge, String status) {
        if (status.equals(edge.getStatus())
                || (oppNetRules != null && !oppNetRules.statusAllowed(edge, status))) {
            return false;
        }

        boolean changed = edge.setStatus(status);
        if (changed) {
            logDGS("ce " + edge.toDGS(false));
            resetNodeStatus(edge, OppNetRules.CHANGED);
            notifyEdgeListeners(edge, EDGE_CHANGED);
        }
        return changed;
    }

    //-------------------------------------------------------------------------
    @Override
    public synchronized String getEdgeStatus(String nodeId1, String nodeId2,
            String connectivityType) {
        String edgeId = edgeFactory.makeEdgeId(nodeId1, nodeId2,
                connectivityType);
        OppEdge edge = getEdge(edgeId);
        if (edge != null) {
            return edge.getStatus();
        }
        return null;
    }

    //-------------------------------------------------------------------------
    @Override
    public Collection<String> getNeighbors(String nodeId,
            String connectivityType, String edgeStatus) {
        Collection<String> neighbors = new HashSet<>();
        Collection<OppNode> neighborsNodes = getNeighborsNodes(nodeId, connectivityType, edgeStatus);
        if (neighborsNodes != null) {
            for (OppNode neighbor : neighborsNodes) {
                neighbors.add(neighbor.getId());
            }
        }
        return neighbors;
    }

    //-------------------------------------------------------------------------
    @Override
    public int nbNeighbors(String nodeId,
            String connectivityType, String edgeStatus) {
        Collection<OppNode> neighborsNodes = getNeighborsNodes(nodeId, connectivityType, edgeStatus);
        if (neighborsNodes == null) {
            return 0;
        } else {
            return neighborsNodes.size();
        }
    }

    /**
     * Give the neighbor nodes of the node for a given connectivity type and
     * status. If connectivityType is null, give all neighbors for any
     * connectivity type. If status is null, give all neighbors for any status.
     *
     * @param nodeId a node id.
     * @param connectivityType a connectivity type. May be null.
     * @param edgeStatus an edge status. May be null.
     * @return nodes having edges with the given status and connectivity type.
     */
    public Collection<OppNode> getNeighborsNodes(String nodeId,
            String connectivityType, String edgeStatus) {
        OppNode node = getNode(nodeId);
        if (node != null) {
            return node.getNeighbors(connectivityType, edgeStatus);
        }
        return null;
    }

    //-------------------------------------------------------------------------
    @Override
    public boolean areNeighbors(String nodeId1, String nodeId2,
            String connectivityType, String edgeStatus) {
        OppNode node1 = getNode(nodeId1);
        OppNode node2 = getNode(nodeId2);
        if (node1 != null && node2 != null) {
            return node1.isNeighbor(node2, connectivityType, edgeStatus);
        }

        return false;
    }

    //-------------------------------------------------------------------------
    @Override
    public synchronized OppEdge removeEdge(String id) {
        OppEdge e = getEdge(id);
        if (e != null) {
            return removeEdge(e);
        }
        return null;
    }

    //-------------------------------------------------------------------------
    /*
     * Override the removeEdge method to notify listeners and reset
     * nodes status.
     */
    @Override
    public synchronized OppEdge removeEdge(Edge e) {
        OppEdge edge = super.removeEdge(e);
        if (edge != null) {
            logDGS("de " + edge.getId());
            resetNodeStatus(edge, OppNetRules.REMOVED);
            notifyEdgeListeners(edge, EDGE_REMOVED);
        }
        return edge;
    }

    //-------------------------------------------------------------------------
    /*
     * Override the addEdge method to notify listeners and reset
     * nodes status.
     */
    @Override
    public synchronized OppEdge addEdge(String id, Node node1, Node node2) {

        OppEdge edge = getEdge(id);
        if (edge != null) {
            return edge;
        }

        edge = super.addEdge(id, node1.getId(), node2.getId());

        if (edge != null) {
            edge.init();
            logDGS("ae " + edge.toDGS(true));
            resetNodeStatus(edge, OppNetRules.ADDED);
            notifyEdgeListeners(edge, EDGE_ADDED);
        }

        return edge;
    }

    /**
     * Check whether the current and the given nodes are within mutual radio
     * range for the given connectivity type.
     *
     * @param node2 a node
     * @param connectivityType a connectivity type
     * @return true if the current node and the given node are within mutual
     * radio range for this connectivity type.
     */
    private boolean areInRange(OppNode node1, OppNode node2, String connectivityType) {
        if (!node1.isOnline() || !node1.hasConnectivityType(connectivityType)
                || !node2.isOnline() || !node2.hasConnectivityType(connectivityType)) {
            return false;
        }

        CoordCar coord1 = node1.getCoord();
        CoordCar coord2 = node2.getCoord();
        if (coord1 == null || coord2 == null) {
            return false;
        }
        long range = this.connectivityProfiles.getRange(connectivityType);
        double distance = coord1.distanceTo(coord2);
        return distance <= range;
    }

    //-------------------------------------------------------------------------
    // Private methods - reset/remove edges for a node
    //-------------------------------------------------------------------------
    /*
     * Add all possible edges for a node when the node is online.
     */
    private void resetEdges(OppNode node) {
        for (String type : node.getConnectivityTypes()) {
            resetEdges(node, type);
        }
    }

    //-------------------------------------------------------------------------
    /*
     * Add all possible edges for a node for the given connectivity
     * type. The node is online and has this type.
     */
    private void resetEdges(OppNode node, String type) {
        Collection<OppNode> nodes = getNodeSet();
        edgeFactory.setConnectivityType(type);
        for (OppNode node2 : nodes) {
            if (node != node2) {
                String edgeId = edgeFactory.makeEdgeId(node, node2, type);
                if (getEdge(edgeId) == null && areInRange(node, node2, type)) {
                    addEdge(edgeId, node, node2);
                }
            }
        }
    }

    //-------------------------------------------------------------------------
    /*
     * Remove all the node's edges when the node is offline.
     */
    protected void removeAllEdges(OppNode node) {
        for (int i = node.getDegree() - 1; i >= 0; i--) {
            OppEdge edge = node.getEdge(i);
            removeEdge(edge);
        }
    }

    //-------------------------------------------------------------------------
    /*
     * Remove all the node's edges for the given connectivity type.
     */
    private void removeEdges(OppNode node, String type) {
        for (int i = node.getDegree() - 1; i >= 0; i--) {
            OppEdge edge = node.getEdge(i);
            if (edge.getConnectivityType().equals(type)) {
                removeEdge(edge);
            }
        }
    }

    //-------------------------------------------------------------------------
    /**
     * Change the nodes status according to the edge status, following the
     * network rules.
     *
     * @param edge an edge between the nodes
     * @param removed true if the edge has been removed
     */
    private void resetNodeStatus(OppEdge edge, String command) {
        if (oppNetRules == null) {
            return;
        }

        String[] status = oppNetRules.nodeStatus(edge, command);
        if (status != null) {
            String type = edge.getConnectivityType();
            setNodeStatus((OppNode) edge.getSourceNode(), type, status[0]);
            setNodeStatus((OppNode) edge.getTargetNode(), type, status[1]);
        }
    }

    //-------------------------------------------------------------------------
    // Private methods - DGS
    //-------------------------------------------------------------------------
    /**
     * Write a DGS line preceded by a 'st' line if needed in the dgsWriter, if
     * it is not null. <code>lastLogTime</code> is the previous 'st' line
     * written (-1 at the beginning)
     *
     * @param line the DGS line
     */
    protected final void logDGS(String line) {
        if (dgsWriter != null) {
            long time = getCurrentStep();
            if (lastLogTime < time) {
                lastLogTime = time;
                println(dgsWriter, "st " + time);
            }
            println(dgsWriter, line);
        }
    }

    //-------------------------------------------------------------------------
    /**
     * Write a line in the given writer, if it is not null
     */
    protected void println(PrintWriter writer, String line) {
        if (writer == null) {
            return;
        }
        writer.println(line);
    }

    //-------------------------------------------------------------------------
    // Edge & node listeners
    //-------------------------------------------------------------------------
    @Override
    public void addEdgeListener(String nodeId,
            String connectivityType, OppEdgeListener listener) {
        if (connectivityType == null) {
            connectivityType = defaultConnectivityType;
        }
        edgeListeners.put(nodeId + " " + connectivityType, listener);
    }

    //-------------------------------------------------------------------------
    @Override
    public void removeEdgeListener(String nodeId, String connectivityType) {
        if (connectivityType == null) {
            connectivityType = defaultConnectivityType;
        }
        edgeListeners.remove(nodeId + " " + connectivityType);
    }

    //-------------------------------------------------------------------------
    @Override
    public void addNodeListener(String nodeId, OppNodeListener listener) {
        nodeListeners.put(nodeId, listener);
    }

    //-------------------------------------------------------------------------
    @Override
    public void removeNodeListener(String nodeId) {
        nodeListeners.remove(nodeId);
    }

    //-------------------------------------------------------------------------
    protected void notifyNodeListeners(OppNode node, String command) {
        if (console != null) {
            console.notifyNodeListeners(node, command);
        }

        OppNodeListener listener = nodeListeners.get(node.getId());
        if (listener != null) {
            switch (command) {
                case NODE_ADDED:
                    listener.nodeAdded(node.getId());
                    break;
                case NODE_REMOVED:
                    listener.nodeRemoved(node.getId());
                    break;
                case NODE_MOVED:
                    listener.nodeMoved(node.getId(), node.getCoord());
                    break;
            }
        }
    }

    //-------------------------------------------------------------------------
    protected void notifyEdgeListeners(OppEdge edge, String command) {
        if (console != null) {
            console.notifyEdgeListeners(edge, command);
        }

        if (hub != null) {
            hub.notifyEdgeListeners(edge, command);
        }

        String nodeId1 = edge.getSourceNode().getId();
        String nodeId2 = edge.getTargetNode().getId();
        String type = edge.getConnectivityType();
        String status = edge.getStatus();

        OppEdgeListener listener = edgeListeners.get(nodeId1 + " " + type);
        if (listener != null) {
            notifyEdgeListener(listener, nodeId2, status, command);
        }

        listener = edgeListeners.get(nodeId2 + " " + type);
        if (listener != null) {
            notifyEdgeListener(listener, nodeId1, status, command);
        }
    }

    //-------------------------------------------------------------------------
    private void notifyEdgeListener(OppEdgeListener listener,
            String nodeId, String status, String command) {
        switch (command) {
            case EDGE_ADDED:
                listener.edgeAdded(nodeId, status);
                break;
            case EDGE_REMOVED:
                listener.edgeRemoved(nodeId, status);
                break;
            case EDGE_CHANGED:
                listener.edgeChanged(nodeId, status);
                break;
        }
    }

    //-------------------------------------------------------------------------
    // Nodes history (an & dn events)
    //-------------------------------------------------------------------------
    private List<NodeEvent> makeEvents(String nodesHist) {
        List<NodeEvent> events = new ArrayList<>();
        String[] parts = nodesHist.split(";");

        for (String nodeStep : parts) {
            String[] tokens = nodeStep.split(",");
            if (tokens.length >= 4) {
                long startStep = Long.parseLong(tokens[0]);
                long endStep = Long.parseLong(tokens[1]);
                String nodeId = tokens[3];
                events.add(new NodeEvent("an", startStep, nodeId));
                if (endStep > 0) {
                    events.add(new NodeEvent("dn", endStep, nodeId));
                }
            }
        }
        // sort events
        NodeEvent[] array = new NodeEvent[events.size()];
        events.toArray(array);
        Arrays.sort(array);
        return Arrays.asList(array);
    }

    //-------------------------------------------------------------------------
    class NodeEvent implements Comparable<NodeEvent> {

        String eventName; // an, dn
        String nodeId;    // the id of the node
        long step;        // the step time

        public NodeEvent(String eventName, long step, String nodeId) {
            this.eventName = eventName;
            this.step = step;
            this.nodeId = nodeId;
        }

        public void doEvent() {
            if (eventName.equals("an")) {
                addNode(nodeId, null);
            } else if (eventName.equals("dn")) {
                deleteNode(nodeId);
            }
        }

        @Override
        public int compareTo(NodeEvent event) {
            if (step < event.step) {
                return -1;
            } else if (step > event.step) {
                return 1;
            }
            return 0;
        }
    }
}
