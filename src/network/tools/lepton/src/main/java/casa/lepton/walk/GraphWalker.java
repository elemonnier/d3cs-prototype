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
import casa.util.geom.Circle;
import casa.util.geom.CoordCar;
import casa.util.geom.Polygon;
import casa.util.geom.Rectangle;
import casa.util.geom.Shape;
import java.util.List;
import java.util.Vector;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.graphstream.graph.Path;

/**
 * The mobility of a mobile element that moves along an underlying graph.
 *
 */
public class GraphWalker implements Walker {

    protected GraphWalk walk_;
    public String pauseType = null;

    protected Step step_;
    protected double speed_;

    protected Node departureNode_;
    protected Node arrivalNode_;

    protected List<Node> path_;

    protected GraphWalker() { //FR: ajouté pour surcharge du constructeur
    }

    // ------------------------------------------------------------
    public GraphWalker(GraphWalk walk, long time,
            String pauseType) {

        walk_ = walk;
        if (pauseType != null) {
            this.pauseType = pauseType + ":";
        }

        Node node;
        long pauseDuration = 0;
        speed_ = 0.0;

        // Some of the walkers should move immediately upon their
        // creation, others should wait for a while before starting
        // moving
        boolean paused = (walk_.random.nextDouble() < 0.5);

        if (paused) {
            // "Paused" walkers are selected among graph nodes whose
            // "area" attributes are of type "pauseType"
            node = selectNode(pauseType);
            pauseDuration = (long) getUniformValue(0, walk_.maxWait);
        } else // Other walkers can start moving from any graph node
        {
            node = selectNode(null);
        }

        CoordCar pos = getCoordAround(node);
        departureNode_ = node;
        arrivalNode_ = node;

        step_ = new Step(pos, pos, time, 0.0, pauseDuration);
    }

    // ------------------------------------------------------------
    public Walk getWalk() {

        return walk_;
    }

    // ------------------------------------------------------------
    public Step getStep() {

        return step_;
    }

    // ------------------------------------------------------------
    protected CoordCar getCoord(Node node) {

        DGSAttributes nodeAttributes = new DGSAttributes(node);
        double x = nodeAttributes.getDouble("x", 0);
        double y = nodeAttributes.getDouble("y", 0);

        return new CoordCar(x, y);
    }

    // ------------------------------------------------------------
    protected Shape getShape(String id, String area) {

        Shape shape = walk_.getShape(id);
        if (shape != null) {
            return shape;
        }

        int idx = area.indexOf(":");
        String type = area.substring(0, idx);
        String data = area.substring(idx + 1);
        // System.out.println("We've got a " + type + " area!");

        if (type.equals("polygon")) {
            shape = new Polygon(data);
        } else if (type.equals("circle")) {
            shape = new Circle(data);
        } else if (type.equals("rectangle")) {
            shape = new Rectangle(data);
        }

        walk_.putShape(id, shape);
        return shape;
    }

    // ------------------------------------------------------------
    protected CoordCar getCoordAround(Node node) {

        DGSAttributes nodeAttributes = new DGSAttributes(node);
        String area = nodeAttributes.get("area");
        if (area != null) {
            Shape shape = getShape(node.getId(), area);

            if (shape != null) {
                return shape.getPoint(walk_.random);
            }
        }

        double x = nodeAttributes.getDouble("x", 0);
        double y = nodeAttributes.getDouble("y", 0);
        return new CoordCar(x, y);
    }

    // ------------------------------------------------------------
    protected double getUniformValue(double min, double max) {

        return min + (walk_.random.nextDouble() * (max - min));
    }

    // ------------------------------------------------------------
    public CoordCar getPosition(long time) {

        if (time >= step_.timeOfCompletion()) {
            nextStep(time);
            return step_.departure();
        }

        return step_.getPosition(time);
    }

    // ------------------------------------------------------------
    protected Node selectNode(String pauseType) {

        int nbNodes = walk_.graph.getNodeCount();
        Node node;
        boolean found = false;

        do {
            int idx = walk_.random.nextInt(nbNodes);
            node = walk_.graph.getNode(idx);
            if (pauseType == null) {
                found = true;
            } else {
                DGSAttributes nodeAttributes = new DGSAttributes(node);
                String area = nodeAttributes.get("area");
                found = (area != null) && (area.startsWith(pauseType));
            }
        } while (!found);

        return node;
    }

    // ------------------------------------------------------------
    public void computeNextPath(long time) {

        departureNode_ = arrivalNode_; //FR deja fait avant l'appel dans nextStep(time)

        // Choose new arrival node
        Node targetNode = selectNode(pauseType);

        // Compute path from departureNode_ to targetNode
        if (targetNode == departureNode_) {
            path_ = new Vector<Node>(2);
            path_.add(departureNode_);
            path_.add(departureNode_);
        } else {
            Path p = walk_.getShortestPath(departureNode_.getId(),
                    targetNode.getId());

            if (p != null) {
                path_ = p.getNodePath();
            } else {
                path_ = null;
            }

            if (path_ == null) {
                System.err.println("Warning: no path found from " + departureNode_
                        + " to " + targetNode);
            }
        }

        // Choose speed for this path (Uniform distribution)
        speed_ = getUniformValue(walk_.minSpeed,
                walk_.maxSpeed);

//        System.out.print("New path from " + departureNode_.getId()
//                + " to " + targetNode.getId() + ": [");
//        if (path_ == null) {
//            System.out.println(" null ]");
//        } else {
//            for (Node n : path_) {
//                System.out.print(" " + n);
//            }
//            System.out.println(" ]");
//        }
    }

    // ------------------------------------------------------------
    protected Step getStep(long time, Node depNode, Node arrNode,
            boolean endOfPath) {

        // Get departure and arrival positions
        // Coord departure = getCoord(depNode);
        // Coord arrival = getCoord(arrNode);
        // FG
        CoordCar departure = step_.arrival();
        CoordCar arrival = getCoordAround(arrNode);

        // FG: Speed is now determined for a whole path (i.e. several
        // successive steps)
        // Choose speed - Uniform distribution
        // double speed = getUniformValue(walk_.minSpeed,
        // walk_.maxSpeed);
        // Choose pause duration - ψ(∆tp) ∼ 1/∆tp^(1+β)
        // long pauseDuration = (long)getLevyValue(minWaitTime,
        // maxWaitTime, beta_);
        // Choose pause duration - Uniform distribution
        long pauseDuration;
        if (endOfPath) {
            pauseDuration = (long) getUniformValue(walk_.minWait,
                    walk_.maxWait);
        } else {
            pauseDuration = 0;
        }

        return new Step(departure, arrival,
                time, speed_,
                pauseDuration);
    }

    // ------------------------------------------------------------
    public Step nextStep2(long time) {

        departureNode_ = arrivalNode_;

        // Choose new arrival node among neighbors of departure node
        int outDegree = departureNode_.getOutDegree();
        int idx = walk_.random.nextInt(outDegree);
        Edge edge = departureNode_.getLeavingEdge(idx);
        arrivalNode_ = edge.getOpposite(departureNode_);

        step_ = getStep(time, departureNode_, arrivalNode_, true);

        return step_;
    }

    // ------------------------------------------------------------
    public Step nextStep(long time) {

        departureNode_ = arrivalNode_;

        if ((path_ == null) || path_.isEmpty()) {
            do {
                computeNextPath(time);
            } while (path_ == null);
            // First node in path should be departureNode_
            if (!path_.isEmpty()) {
                path_.remove(0);
            }
        }

        arrivalNode_ = path_.get(0); //FR plus simple: arrivalNode_= path_.remove(0);
        path_.remove(0);

        boolean endOfPath = path_.isEmpty();
        step_ = getStep(time, departureNode_, arrivalNode_, endOfPath);

//        System.out.println("next step=" + step_);
        return step_;
    }

    // ------------------------------------------------------------
    public Step nextStep() {

        long time = step_.timeOfCompletion();
        // computeNextPath(time);
        return nextStep(time);
    }
}
