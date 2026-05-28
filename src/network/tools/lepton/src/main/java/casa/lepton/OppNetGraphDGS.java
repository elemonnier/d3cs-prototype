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

import casa.lepton.conf.OppNetProperties;
import casa.dgs.DGSGraph;
import casa.dgs.DGSAttributes;
import casa.util.geom.AreaCar;
import casa.util.geom.CoordCar;
import java.io.IOException;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.TimeZone;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;

/**
 * A {@link OppNetGraph} read from an input DGS file.
 *
 */
public class OppNetGraphDGS extends OppNetGraph {

    private final DGSGraph dgsGraph;         // graph read from the DGS file

    /**
     * Constructor.
     *
     * @param networkId a network id.
     * @param dgsFile a source dgs file name
     * @param props properties
     * @throws java.io.IOException
     */
    public OppNetGraphDGS(String networkId, String dgsFile, OppNetProperties props) throws IOException {
        super(networkId, props);

        this.dgsGraph = new DGSGraph(networkId + "-0", dgsFile);
        this.dgsGraph.initGraph();
        this.currentStep = dgsGraph.getCurrentStep();
        this.refTime = dgsGraph.getRefTime();
        TimeZone dgsTimezone = dgsGraph.getTimeZone();
        if (dgsTimezone != null) {
            this.timezone = dgsTimezone;
        }

        // write dgs ref_time
        if (dgsWriter != null && refTime != 0) {
            addAttribute("ref_time", refTime);
            println(dgsWriter, "cg " + graphAttributes.toString("ref_time"));
        }

        makeStep();

        AreaCar graphArea = dgsGraph.getArea();
        if (graphArea != null) {
            setArea(graphArea);
        } 
    }

    //---------------------------------------------------------------
    @Override
    public boolean step() {

        boolean running = dgsGraph.step();
        currentStep = dgsGraph.getCurrentStep();

        waitUntil(currentStep);

//        System.err.println("Step " + currentStep);
        super.stepBegins(currentStep);

        makeStep();

        return running;
    }

    //---------------------------------------------------------------
    // Add/delete nodes
    //---------------------------------------------------------------
    @Override
    public synchronized void addNode(String nodeId, String profile) {
        // DO NOTHING: nodes are only added by this instance
        // and cannot be added from an other object (eg the hub)
    }

    @Override
    public synchronized void deleteNode(String nodeId) {
        // DO NOTHING: nodes are only removed by this instance
        // and cannot be removed from an other object (eg the hub)
    }

    private void clearGraph() {
        this.clear();
    }

    //---------------------------------------------------------------
    private void makeStep() {

        // TODO notify node and edge listeners (?)
        // update graph area
        if (dgsGraph.graphChanged()) {
            AreaCar dgsArea = dgsGraph.getArea();
            if (!Objects.equals(area, dgsArea)) {
                this.setArea(dgsArea);
            }
        }
        // update nodes
        Set<OppNode> movedNodes = new HashSet<>();
        for (String nodeId : dgsGraph.nodeChanged()) {
            Node dgsNode = dgsGraph.getNode(nodeId);
            if (dgsNode == null) {
                removeNode(nodeId);
            } else {
                OppNode movedNode = updateNode(nodeId, dgsNode);
                if (movedNode != null && makeEdges) {
                    movedNodes.add(movedNode);
                }
            }
        }
        // update edges
        if (makeEdges) {
            updateEdges(movedNodes);
        } else {
            for (String edgeId : dgsGraph.edgeChanged()) {
                Edge dgsEdge = dgsGraph.getEdge(edgeId);
                if (dgsEdge == null) {
                    removeEdge(edgeId);
                } else {
                    updateEdge(edgeId, dgsEdge);
                }
            }
        }
    }

    //-------------------------------------------------------------------------
    /**
     * Update or add a adge with the given edgeId according to the given edge
     *
     * @param edgeId
     * @param dgsEdge
     */
    private void updateEdge(String edgeId, Edge dgsEdge) {

        boolean changed = false;
        DGSAttributes dgsEdgeAttributes = new DGSAttributes(dgsEdge);

        OppEdge edge = getEdge(edgeId);
        String dgsType = dgsEdgeAttributes.get("type");
        String dgsStatus = dgsEdgeAttributes.get("status");
        String dgsTag = dgsEdgeAttributes.get("tag");

        if (edge == null) {
            edgeFactory.setConnectivityType(dgsType);
            edgeFactory.setStatus(dgsStatus);
            Node source = dgsEdge.getSourceNode();
            Node target = dgsEdge.getTargetNode();
            super.addEdge(edgeId, source, target);
            edge = getEdge(edgeId);

        } else {

            DGSAttributes edgeAttributes = new DGSAttributes(edge);

            String type = edgeAttributes.get("type");
            if (dgsType != null && !Objects.equals(type, dgsType)) {
                edge.setConnectivityType(dgsType);
            }
            String status = edgeAttributes.get("status");
            if (dgsStatus != null && !Objects.equals(status, dgsStatus)) {
                edge.setStatus(dgsStatus);
            }
        }

        String tag = edge.getTag();
        if (!Objects.equals(tag, dgsTag)) {
            edge.setTag(dgsTag);
            changed = true;
        }

        if (changed) {
            String str = edge.toDGS(false).trim();
            if (!str.equals(edge.getId())) {
                logDGS("ce " + str);
            }
        }
    }

    //-------------------------------------------------------------------------
    /**
     * Update or add a node with the given nodeId according to the given node
     *
     * @param nodeId the id of the node to be added or updated
     * @param dgsNode the node to be "cloned"
     * @return the new node if it has moved (else null)
     */
    private OppNode updateNode(String nodeId, Node dgsNode) {

        boolean moved = false, changed = false;
        OppNode node = getNode(nodeId);
        CoordCar dgsCoord = dgsGraph.getCoord(dgsNode);

        DGSAttributes nodeAttributes = new DGSAttributes(dgsNode);

        if (node == null) { // add node

            if (dgsCoord != null) {
                nodeFactory.setCoord(dgsCoord);
            }
            String label = nodeAttributes.get("label");
            nodeFactory.setLabel(label);
            String profile = nodeAttributes.get("profile");
            super.addNode(nodeId, profile);
            node = getNode(nodeId);
            moved = true;

        } else { // update coord if needed

            CoordCar coord = node.getCoord();
            if (!Objects.equals(coord, dgsCoord)) {
                node.setCoord(dgsCoord);
                moved = true;
            }
        }

        if (nodeAttributes.has("online")) {
            boolean online = nodeAttributes.getBoolean("online", true);
            if (online != node.isOnline()) {
                node.setOnline(online);
                moved = true;
            }
        }

        String dgsLabel = nodeAttributes.get("label");
        if (dgsLabel == null) {
            dgsLabel = nodeAttributes.get("ui.label");
        }
        String label = node.getLabel();
        if (!Objects.equals(label, dgsLabel)) {
            node.setLabel(dgsLabel);
            changed = true;
        }

        String dgsTag = nodeAttributes.get("tag");
        String tag = node.getTag();
        if (!Objects.equals(tag, dgsTag)) {
            node.setTag(dgsTag);
            changed = true;
        }

        if (moved || changed) {
            String str = node.toDGS().trim();
            if (!str.equals(node.getId())) {
                logDGS("cn " + str);
            }
        }
        notifyNodeListeners(node, NODE_MOVED);

        if (moved) {
            return node;
        }
        return null;
    }
}
