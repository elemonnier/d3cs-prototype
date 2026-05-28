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
package casa.lepton.walk;

import java.io.BufferedReader;
import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.TimeZone;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Graph;
import org.graphstream.graph.Node;
import org.graphstream.graph.Path;

/**
 * A bus journey along bus line paths, represented by an ordered list of paths
 * between bus stops having each a start and end time.
 *
 */
public class BusJourney {

    /**
     * The date format of the stops times.
     */
    public static final DateFormat DATE_FORMAT = new SimpleDateFormat("HH.mm", Locale.FRANCE);

    static {
        DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    /**
     * The name of a edge attribute that gives the edge length (distance between
     * its source and target nodes).
     */
    private static final String LENGTH = "length";

    /**
     * The name of a edge attribute that gives the name of the stop represented
     * by its target edge.
     */
    private static final String END_STOP = "endstop";

    private final Graph graph;             // the graph with possibly some attributes (e.g. line name and color)
    private final List<BusPath> paths;     // the list of paths between successive bus stops
    private final String busName;          // the name of the bus
    private final List<Path> lines;        // the lines along which the bus drives
    private long startTime, endTime;       // the start and end times of the bus journey

    private int endLineIdx = -1, endEdgeIdx;

    /**
     * Create an empty bus journey.
     *
     * @param graph the graph that hosts the nodes and edges of the bus paths
     * @param busName the name of the bus
     * @param lines
     */
    public BusJourney(Graph graph, String busName, List<Path> lines) {
        this.graph = graph;
        this.paths = new ArrayList<>();
        this.busName = busName;
        this.lines = lines;
    }

    /**
     * Give the name of the bus.
     *
     * @return the name of the bus
     */
    public String getBusName() {
        return busName;
    }

    /**
     * Give the time when the bus leaves the first node of the journey.
     *
     * @return the start time of the bus journey
     */
    public long getStartTime() {
        return startTime;
    }

    /**
     * Give the time when the bus arrives at the last node of the journey.
     *
     * @return the end time of the bus journey
     */
    public long getEndTime() {
        return endTime;
    }

    /**
     * Give an iterator over nodes that compose this journey.
     *
     * @param pauseSeed the seed used to create a random generator of pause
     * durations
     * @return iterator over nodes of this journey
     */
    public Iterator<BusNode> iterator(long pauseSeed) {
        return new BusJourneyIterator(paths.iterator(), new RandomPauseDurationGenerator(pauseSeed));
    }

    /**
     * Give an iterator over nodes that compose this journey.
     *
     * @param pauseGenerator to generate pauses durations
     * @return iterator over nodes of this journey
     */
    public Iterator<BusNode> iterator(PauseDurationGenerator pauseGenerator) {
        return new BusJourneyIterator(paths.iterator(), pauseGenerator);
    }

    /**
     * Load a journey from an input stream which next line contains the name of
     * the journey. After this method, the last line of the input stream is
     * either null or an empty line.
     *
     * @param graph the graph that contains the nodes and edges of the lines
     * @param lines the paths representing the bus lines
     * @param reader input stream
     * @return a bus journey or null if the next line of the reader is null or
     * empty
     * @throws IOException if an error occurs while reading the input stream
     * @throws ParseException if a read line has a wrong format
     */
    public static BusJourney loadJourney(Graph graph, List<Path> lines, BufferedReader reader) throws IOException, ParseException {
        String line = reader.readLine();
        if (line != null && !line.equals("")) {
            BusJourney journey = new BusJourney(graph, line, lines);
            line = reader.readLine();
            while (line != null && !line.equals("")) {
                String[] args = line.split(" ");
                if (args.length == 3) {
                    journey.addPath(Integer.parseInt(args[0]),
                            Integer.parseInt(args[1]),
                            DATE_FORMAT.parse(args[2]).getTime());
                } else {
                    throw new ParseException("Wrong line format: " + line, 0);
                }
                line = reader.readLine();
            }
            return journey;
        }
        return null;
    }

    //-------------------------------------------------------------------------
    // Private methods
    //-------------------------------------------------------------------------
    /**
     * Add a path between the last bus stop in the journey and this one.
     *
     * @param lineIdx the index of the edge which target node represents the
     * last bus stop of the bus path
     * @param edgeIdx the time when the bus arrives at the target node of the
     * last edge
     * @param time
     */
    private void addPath(int lineIdx, int edgeIdx, long time) {
        if (lineIdx == endLineIdx) {
            addPath(lineIdx, endEdgeIdx, endTime, edgeIdx, time);
        }
        endLineIdx = lineIdx;
        endEdgeIdx = edgeIdx;
        endTime = time;
    }

    /**
     * Add a new path between two bus stops. If the source node of startEdge and
     * the target node of the previous endEdge are not the same, add a new edge
     * at the end of the previous path.
     *
     * @param lineIdx the index of a path that contains the given startEdge and
     * endEdge
     * @param startEdgeIdx the index of the edge which source node represents
     * the first bus stop of the bus path
     * @param startTime the time when the bus leaves the source node of first
     * edge
     * @param endEdgeIdx the index of the edge which target node represents the
     * last bus stop of the bus path
     * @param endTime the time when the bus arrives at the target node of the
     * last edge
     */
    private void addPath(int lineIdx, int startEdgeIdx, long startTime, int endEdgeIdx, long endTime) {

        List<Edge> edges = lines.get(lineIdx).getEdgePath();
        Edge startEdge = edges.get(startEdgeIdx);
        if (paths.isEmpty()) { // this is the first path
            this.startTime = startTime;
        } else { // make a bridge between the last path and the new path
            Edge bridge = makeBridge(paths.get(paths.size() - 1).getEndEdge(), startEdge);
            paths.add(new BusPath(bridge, this.endTime, startTime));
        }

        BusPath busPath = new BusPath(lineIdx, startEdgeIdx, startTime, endEdgeIdx, endTime);
        paths.add(busPath);

        this.endTime = endTime;
    }

    /**
     * Create a 'bridge' between two edges, i.e. a edge that links together the
     * target node of the first edge and the source node of the second edge. If
     * this edge already exists in the graph, return it, or else create a new
     * edge.
     *
     * @param sourceEdge the first edge
     * @param targetEdge the second edge
     * @return a edge between both edges.
     */
    private Edge makeBridge(Edge sourceEdge, Edge targetEdge) {
        String edgeId = sourceEdge.getTargetNode().getId() + "_" + targetEdge.getSourceNode().getId();
        Edge edge = graph.getEdge(edgeId);
        if (edge == null) {
            Node fromNode = sourceEdge.getTargetNode();
            Node toNode = targetEdge.getSourceNode();
            edge = graph.addEdge(edgeId, fromNode, toNode);
        }
        return edge;
    }

    //-------------------------------------------------------------------------
    // Public classes & interfaces
    //-------------------------------------------------------------------------
    /**
     * A node in a bus journey. A node can be an ordinary node or a bus stop.
     * Each node is characterized by the distance to the next node and to the
     * next bus stop and the arrival time at the next bus stop
     */
    public class BusNode {

        private final long pauseDuration;        // the pause duration at this stop (start time - arrival time) 
        private final long totalPauseDuration;   // the total duration of the pauses until the next stop 
        private final long nextStopTime;         // the arrival time at the next bus stop
        private final double x, y;               // the location of the node
        private final double nextNodeDistance;   // the distance between this node and the next node
        private final double nextStopDistance;   // the distance between this node and the next stop node

        /**
         * Create a new stop node.
         *
         * @param x x location
         * @param y y location
         * @param nextNodeDistance distance between this node and the next node
         * @param nextStopDistance distance between this node and the next stop
         * node
         * @param pauseDuration pause duration between at this stop
         * @param nextStopTime arrival time at the next stop node
         */
        private BusNode(double x, double y, double nextNodeDistance, double nextStopDistance, long pauseDuration, long nextStopTime, long totalPauseDuration) {
            this.x = x;
            this.y = y;
            this.nextNodeDistance = nextNodeDistance;
            this.nextStopDistance = nextStopDistance;
            this.pauseDuration = pauseDuration;
            this.nextStopTime = nextStopTime;
            this.totalPauseDuration = totalPauseDuration;
        }

        /**
         * Give the x location of the node.
         *
         * @return the x location of the node
         */
        public double getX() {
            return x;
        }

        /**
         * Give the y location of the node.
         *
         * @return the y location of the node
         */
        public double getY() {
            return y;
        }

        /**
         * Give the pause duration at this node ie the duration between the
         * arrival time at this node and the departure time from this node.
         *
         * @return the pause duration at this node
         */
        public long getPauseDuration() {
            return pauseDuration;
        }

        /**
         * Give the arrival time at the next node in the bus journey.
         *
         * @param departureTime the departure time from this node
         * @return the arrival time at the next node
         */
        public long getNextNodeArrivalTime(long departureTime) {
            if (nextStopDistance > 0.1) {
                return Math.round(departureTime + nextNodeDistance * (nextStopTime - totalPauseDuration - departureTime) / nextStopDistance);
            } else {
                System.err.println(DATE_FORMAT.format(nextStopTime - departureTime));
                return nextStopTime;
            }
        }
    }

    //-------------------------------------------------------------------------
    /**
     * Interface that defines a pause duration generator to calculate pause
     * durations at each stop node.
     */
    public interface PauseDurationGenerator {

        /**
         * Give the sum of the pauses durations at all the stops of a path. A
         * path is a journey between two bus stops having fixed arrival times,
         * crossing intermediate stops. This duration is used to evaluate the
         * speed of the bus between each stop in order to arrive at the end of
         * the path at a fixed time. It is called at each bus stop. It can be
         * reevaluated
         *
         * @param nbStops the number of stops in the path (the last stop
         * excluded)
         * @return the total duration of the pauses in the path
         */
        public long pathPauseDuration(int nbStops);

        /**
         * Give the pause duration at a stop. This stop is either the first bus
         * stop in a path or an intermediate bus stop.
         *
         * @param nbStops the number of stops that remain in the path (this stop
         * included)
         * @return the pause duration at the stop
         */
        public long stopPauseDuration(int nbStops);

    }

    //-------------------------------------------------------------------------
    // Private classes
    //-------------------------------------------------------------------------
    /**
     * A random pause duration generator.
     */
    private class RandomPauseDurationGenerator implements PauseDurationGenerator {

        private static final long MIN_PAUSE = 10000, MAX_PAUSE = 20000;

        private final Random random;                  // random object to generate pause times
        private long pathPauseDuration;

        /**
         * Constructor
         */
        public RandomPauseDurationGenerator() {
            this(System.currentTimeMillis());
        }

        /**
         * Constructor
         *
         * @param seed the seed for the random generation of pauses durations
         */
        public RandomPauseDurationGenerator(long seed) {
            this.random = new Random(seed);
        }

        @Override
        public long pathPauseDuration(int nbStops) {
            if (nbStops == 0) {
                pathPauseDuration = 0;
            } else if (pathPauseDuration == 0) {
                pathPauseDuration = nbStops * (random.nextInt((int) (MAX_PAUSE - MIN_PAUSE)) + MIN_PAUSE);
            }
            return pathPauseDuration;
        }

        @Override
        public long stopPauseDuration(int nbStops) {
            long pauseDuration = 0;
            if (nbStops == 1) { // last stop in this path
                pauseDuration = pathPauseDuration;
            } else if (random.nextBoolean()) {
                pauseDuration = (long) (2 * random.nextDouble() * pathPauseDuration / nbStops);
            }
            pathPauseDuration -= pauseDuration;
            return pauseDuration;
        }
    }

    //-------------------------------------------------------------------------
    /**
     * An iterator over nodes of a bus journey. Pause durations at each bus stop
     * are determined randomly, using the given seed. This iterator is
     * initialized with the bus paths composing the journey and uses their
     * iterators over edges.
     */
    private class BusJourneyIterator implements Iterator<BusNode> {

        private final PauseDurationGenerator pauseGenerator; // to generate pause times

        private final Iterator<BusPath> busPaths;             // iterator over the successive bus paths
        private Iterator<Edge> currentIterator;               // iterator over the current bus path
        private double stopDistance;                          // the distance between the start node of the next edge and the end node of the current path
        private long stopTime;                                // the arrival time at the end node of the current path
        private boolean isStop;                               // true if the source node of the next edge is a bus stop
        private Node targetNode;                              // the target node of the current edge

        private long totalPauseDuration;                      // the total duration of the pauses until the next stop 
        private int nbStops;                                  // the number of intermediate stops until the next stop

        /**
         * Constructor
         *
         * @param busPaths iterator over the successive bus paths
         * @param pauseSeed the seed used to create a random generator of pause
         * duartions durations
         */
        private BusJourneyIterator(Iterator<BusPath> busPaths, PauseDurationGenerator pauseGenerator) {
            this.busPaths = busPaths;
            this.pauseGenerator = pauseGenerator;
        }

        @Override
        public boolean hasNext() {
            return ((currentIterator != null && currentIterator.hasNext())) || busPaths.hasNext() || targetNode != null;
        }

        @Override
        public BusNode next() {
            if (currentIterator == null || !currentIterator.hasNext() && busPaths.hasNext()) {
                // the current bus path is finished. Initialize the next one
                BusPath path = busPaths.next();
                this.currentIterator = path.iterator();
                this.stopDistance = path.length;
                this.stopTime = path.endTime;
                this.nbStops = path.nbStops;
                this.isStop = true; // the first node of a path is always a stop
                this.totalPauseDuration = pauseGenerator.pathPauseDuration(nbStops);
            }

            // look for the next node
            Node node = null;
            long pauseDuration = 0;  // default: no pause 
            double length = 0;

            if (currentIterator != null && currentIterator.hasNext()) {
                Edge edge = this.currentIterator.next();
                node = edge.getSourceNode();
                length = edge.getAttribute(LENGTH);
                targetNode = edge.getTargetNode();
                if (isStop) { // compute the pause duration
                    pauseDuration = pauseGenerator.stopPauseDuration(nbStops);
                    nbStops--;
                    totalPauseDuration = pauseGenerator.pathPauseDuration(nbStops);
                }
                this.isStop = edge.hasAttribute(END_STOP); // true if the next node is a stop

            } else if (targetNode != null) { // the target node of the last edge
                node = targetNode;
                targetNode = null;

            } else {
                throw new NoSuchElementException("Journey finished. No more node");
            }

            double x = node.getAttribute("x");
            double y = node.getAttribute("y");
            return new BusNode(x, y, length, stopDistance, pauseDuration, stopTime, totalPauseDuration);
        }
    }

    //-------------------------------------------------------------------------
    /**
     * A subset of a bus journey between two bus stops, having start and end
     * times. The start and the end stops are in the same bus line or the bus
     * path is composed of a unique edge that forms a bridge between two stops
     * of different lines
     */
    private class BusPath {

        private final long startTime, endTime;  // the start and end times of the bus path
        private double length;                  // the length of the bus path
        private int nbStops;                    // the number of stops in the path (start stop excluded)

        private int lineIdx;                    // the index of the line
        private int startEdgeIdx, endEdgeIdx;   // the indices of the start and end edges
        // or
        private Edge edge;                      // the unique edge of the bus path

        /**
         * Create a path composed of a single edge
         *
         * @param edge the unique edge that composes the path
         * @param startTime the time when the bus leaves the source node of the
         * edge
         * @param endTime the time when the bus arrives at the target node of
         * the edge
         */
        private BusPath(Edge edge, long startTime, long endTime) {
            this.startTime = startTime;
            this.endTime = endTime;
            this.edge = edge;
            this.length += calculateLength(edge);
        }

        /**
         * Create a path between two nodes of a bus line
         *
         * @param lineIdx the index of a line that contains the given startEdge
         * and endEdge
         * @param startEdgeIdx the index of the edge which source node
         * represents the first bus stop of the bus path
         * @param startTime the time when the bus leaves the source node of
         * first edge
         * @param endEdgeIdx the index of the edge which target node represents
         * the last bus stop of the bus path
         * @param endTime the time when the bus arrives at the target node of
         * the last edge
         */
        private BusPath(int lineIdx, int startEdgeIdx, long startTime, int endEdgeIdx, long endTime) {
            this.lineIdx = lineIdx;
            this.startEdgeIdx = startEdgeIdx;
            this.startTime = startTime;
            this.endEdgeIdx = endEdgeIdx;
            this.endTime = endTime;
            this.length = 0;
            for (BusPathIterator it = new BusPathIterator(lineIdx, startEdgeIdx, endEdgeIdx); it.hasNext();) {
                Edge edge = it.next();
                this.length += calculateLength(edge);
                if (edge.hasAttribute(END_STOP)) {
                    nbStops++;
                }
            }
        }

        @Override
        public String toString() {
            if (edge == null) {
                return lineIdx
                        + " " + startEdgeIdx + " " + DATE_FORMAT.format(startTime)
                        + " " + endEdgeIdx + " " + DATE_FORMAT.format(endTime);
            }
            return "";
        }

        private Edge getEndEdge() {
            if (edge == null) {
                return lines.get(lineIdx).getEdgePath().get(endEdgeIdx);
            }
            return edge;
        }

        /**
         * Calculate the edge length and add it if needed to the edge
         * attributes. The edge length is either retrieved from a LENGTH
         * attribute if the edge or calculated from x,y attributes of its source
         * and target nodes.
         *
         * @param edge a edge
         * @return the length of the edge
         */
        private double calculateLength(Edge edge) {
            double l = 0;
            if (edge.hasAttribute(LENGTH)) {
                l = edge.getAttribute(LENGTH);
            } else {
                Node sourceNode = edge.getSourceNode();
                Node targetNode = edge.getTargetNode();
                if (sourceNode.hasAttribute("x") && sourceNode.hasAttribute("y") && targetNode.hasAttribute("x") && targetNode.hasAttribute("y")) {
                    double x1 = sourceNode.getAttribute("x");
                    double y1 = sourceNode.getAttribute("y");
                    double x2 = targetNode.getAttribute("x");
                    double y2 = targetNode.getAttribute("y");
                    l = Math.sqrt((x1 - x2) * (x1 - x2) + (y1 - y2) * (y1 - y2));
                }
                edge.addAttribute(LENGTH, l);
            }
            return l;
        }

        /**
         * Give an iterator over edges between two stops of a bus line
         *
         * @return the iterator
         */
        public Iterator<Edge> iterator() {
            if (edge == null) {
                return new BusPathIterator(lineIdx, startEdgeIdx, endEdgeIdx);
            } else {
                return new EdgeIterator(edge);
            }
        }

        /**
         * An iterator over a path composed of a unique edge
         */
        private class EdgeIterator implements Iterator<Edge> {

            private Edge edge;

            private EdgeIterator(Edge edge) {
                this.edge = edge;
            }

            @Override
            public boolean hasNext() {
                return edge != null;
            }

            @Override
            public Edge next() {
                if (edge != null) {
                    Edge next = edge;
                    edge = null;
                    return next;
                } else {
                    throw new NoSuchElementException("Bus path finished. No more edge");
                }
            }
        }

        /**
         * An iterator over edges obetween two stops of a bus line
         */
        private class BusPathIterator implements Iterator<Edge> {

            private final List<Edge> edges;  // the edges that compose the path
            private final int endEdgeIdx;    // the index of the end edge of this path
            private int nextIdx;             // the index of the next edge to be returned by this iterator

            /**
             * Initialize an iterator positionned on the given startEdge in the
             * given path
             *
             * @param lineIdx the index of a path that contains the given
             * startEdge and endEdge
             * @param startEdgeIdx the index of the edge which source node
             * represents the first bus stop of the bus path
             * @param endEdgeIdx the index of the edge which target node
             * represents the last bus stop of the bus path
             */
            private BusPathIterator(int lineIdx, int startEdgeIdx, int endEdgeIdx) {
                this.edges = lines.get(lineIdx).getEdgePath();
                this.endEdgeIdx = endEdgeIdx;
                setNextIdx(startEdgeIdx);
            }

            @Override
            public boolean hasNext() {
                return nextIdx >= 0;
            }

            @Override
            public Edge next() {
                if (nextIdx < 0) {
                    throw new NoSuchElementException("Bus path finished. No more edge");
                }
                Edge next = edges.get(nextIdx);
                setNextIdx(nextIdx + 1);
                return next;
            }

            /**
             * Set the index of the next edge to be returned by this iterator.
             * If the given index is not valid, set the next index to -1
             *
             * @param nextIdx the index of the next edge
             */
            private void setNextIdx(int nextIdx) {
                if (nextIdx >= 0 && nextIdx < edges.size() && nextIdx <= endEdgeIdx) {
                    this.nextIdx = nextIdx;
                } else {
                    this.nextIdx = -1;
                }
            }
        }
    }
}
