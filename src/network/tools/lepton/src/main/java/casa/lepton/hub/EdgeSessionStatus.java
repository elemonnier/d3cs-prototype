/*
 * License header
 */
package casa.lepton.hub;

import casa.lepton.OppEdge;
import casa.lepton.OppEdgeListener;
import casa.lepton.OppNet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * A class used to combine the sometimes contradictory visions of lepton and the
 * hub concerning the status of edges.
 *
 * Lepton add an edge between two nodes as soon as they are both online and
 * within mutual radio range, and removes it when those conditions are no longer
 * fulfilled.
 *
 * If an edge exists between two nodes, they can open a TCP session via the hub.
 * In that case, the hub informs lepton that the edge status is 'connected'.
 *
 * If, while moving, the nodes move away from each other and become out of
 * range, the edge is removed by lepton. However the hub still considers that
 * they are connected, as long as the TCP session is not used, and the hub is
 * not notified that the edge doesn't exist anymore.
 *
 * If the nodes move close again and an edge is added by lepton, the TCP session
 * is still valid, and this edge should be initialized with the 'connected'
 * status. But lepton cannot change the status of an edge from its defalt value
 * unless it is notified to do so.
 */
public class EdgeSessionStatus {

    private final OppNet oppNet;                       // the graph that maintains edges for nodes within range
    private final Set<String> hubConnectedEdges;       // the edge ids having the CONNECTED status for the hub

    public EdgeSessionStatus(OppNet oppNet) {
        this.oppNet = oppNet;
        this.hubConnectedEdges = new HashSet<>();
    }

    /**
     * Change the status of the edge in the graph if it exists and/or store this
     * status in some cases to restaure it when the edge is created
     *
     * @param nodeId1 a node at one extremity of the edge
     * @param nodeId2 the node at the other extremity of the edge
     * @param connectivityType the connectivity type of the edge
     * @param status the new status (CONNECTED,DISCONNECTED)
     * @return true if
     */
    public boolean setEdgeStatus(String nodeId1, String nodeId2, String connectivityType, String status) {

        boolean changed = false;
        if (oppNet.areNeighbors(nodeId1, nodeId2, connectivityType, null)) {
            // The edge exists in lepton. Change the edge status
            changed = oppNet.setEdgeStatus(nodeId1, nodeId2, connectivityType, status);

        }

        String edgeId = oppNet.makeEdgeId(nodeId1, nodeId2, connectivityType);
        if (changed && status.equals("CONNECTED")) {
            // I need to be notified if this edge is added again (after having been removed) 
            // in order to initialize the status of the new edge to CONNECTED
            hubConnectedEdges.add(edgeId);
        } else if (status.equals("DISCONNECTED")) {
            // The edge is no more considered as CONNECTED.
            // I don't need any more to be notified when the edge is added again
            // as it will be initialized as DISCONNECTED
            hubConnectedEdges.remove(edgeId);
            changed = true;
        }
        return changed;
    }

    public void edgeAdded(OppEdge edge) {
        if (hubConnectedEdges.contains(edge.getId())) {
            oppNet.setEdgeStatus(edge.getNode0().getId(), edge.getNode1().getId(), edge.getConnectivityType(), "CONNECTED");
        }
    }
}
