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

import casa.dgs.DGSAttributes;
import casa.lepton.conf.OppNodeProperties;
import casa.util.geom.AreaCar;
import casa.util.geom.Shape;
import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import org.graphstream.algorithm.AStar;
import org.graphstream.algorithm.AStar.DistanceCosts;
import org.graphstream.graph.Graph;
import org.graphstream.graph.Path;
import org.graphstream.graph.implementations.MultiGraph;
import org.graphstream.stream.file.FileSource;
import org.graphstream.stream.file.FileSourceFactory;

/**
 * An instance of type {@link GraphWalk} defines a mobility model for a random
 * walk that follows edges in a geo-referenced graph.
 */
public class GraphWalk
        implements Walk {

    public AreaCar area;

    public long minWait;
    public long maxWait;
    public double minSpeed;
    public double maxSpeed;
    public String pauseType;
    public Graph graph;
    public Random random;

    private AStar astar_;

    protected static GraphWalk walk_ = null;

    private Map<String, Shape> shapes_
            = new HashMap<String, Shape>();

    // ------------------------------------------------------------
    /**
     * Creates and returns an instance of {@link GraphWalk}, using system
     * properties (if defined) in order to initialize this object, and using
     * default values otherwise.
     *
     * @return a {@link GraphWalk} object, initialized using either system
     * properties or default values
     */
    public static GraphWalk getDefault(OppNodeProperties props) {

        double min_speed = props.getMinSpeed();
        double max_speed = props.getMaxSpeed();

        long min_wait = props.getMinWait();
        long max_wait = props.getMaxWait();

        String pause_type = props.getPauseType();

        long seed = props.getSeed();
        Random random = new Random(seed);

        // read graph
        File graphFile = props.getGraph();
        if (graphFile == null) {
            System.err.println("Missing name of graph file for GraphWalk");
            System.exit(1);
        }
        Graph graph = readGraph(graphFile.getAbsolutePath());
        DGSAttributes graphAttributes = new DGSAttributes(graph);

        // initialize simulation area
        double x = graphAttributes.getDouble("x", 0);
        double y = graphAttributes.getDouble("y", 0);
        double width = graphAttributes.getDouble("width", 0);
        double height = graphAttributes.getDouble("height", 0);
        AreaCar area = new AreaCar(x, y, width, height);
        // System.err.println("area=" + area);

        walk_ = new GraphWalk(area,
                min_wait, max_wait,
                min_speed, max_speed,
                graph,
                pause_type,
                random);

        return walk_;
    }

    // ------------------------------------------------------------
    protected static Graph readGraph(String fname) {

        Graph result = new MultiGraph("graph");
        FileSource fs = null;
        try {
            fs = FileSourceFactory.sourceFor(fname);
        } catch (Exception e) {
            System.err.println("GraphWalk.readGraph(): failed to source for file " + fname);
            System.exit(1);
        } finally {
        }

        fs.addSink(result);

        try {
            fs.readAll(fname);
        } catch (Exception e) {
            System.err.println("GraphWalk.readGraph(): failed to read file " + fname);
            e.printStackTrace(System.err);
            System.exit(1);
        } finally {
        }
        fs.removeSink(result);

        return result;
    }

    // ------------------------------------------------------------
    public GraphWalk(AreaCar area,
            long minWait, long maxWait,
            double minSpeed, double maxSpeed,
            Graph graph,
            String pauseType,
            Random random) {

        this.area = area;
        this.minWait = minWait;
        this.maxWait = maxWait;
        this.minSpeed = minSpeed;
        this.maxSpeed = maxSpeed;
        this.graph = graph;
        this.pauseType = pauseType;
        this.random = random;

        this.astar_ = new AStar(graph);
        this.astar_.setCosts(new DistanceCosts());
    }

    // ------------------------------------------------------------
    @Override
    public Walker getWalker(long time, String nodeId) {

        return new GraphWalker(this, time, pauseType);
    }

    // ------------------------------------------------------------
    public synchronized Path getShortestPath(String departureNode,
            String targetNode) {

        astar_.compute(departureNode, targetNode);
        Path p = astar_.getShortestPath();

        return p;
    }

    // ------------------------------------------------------------
    public synchronized void putShape(String id, Shape shape) {

        shapes_.put(id, shape);
    }

    // ------------------------------------------------------------
    public synchronized Shape getShape(String id) {

        return shapes_.get(id);
    }

    // ------------------------------------------------------------
    @Override
    public AreaCar getArea() {

        return area;
    }

    // ------------------------------------------------------------
    /**
     * Returns a {@link String} representation of this {@link GraphWalk} object.
     *
     * @return a {@link String} representation of this object
     */
//    @Override
//    public String toString() {
//
//        return "Graph Walk -- area=" + area.x + ", " + area.y
//                + " " + area.width + " x " + area.height
//                + ", wait=[" + minWait + "," + maxWait
//                + "], speed=[" + minSpeed + "," + maxSpeed
//                + "], pauseType=" + pauseType;
//    }
}
