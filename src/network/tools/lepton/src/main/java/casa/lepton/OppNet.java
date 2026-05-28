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

import java.util.Collection;

/**
 * This interface represents an opportunistic network composed of devices linked
 * by edges representing actual or possible connections between them.
 *
 */
public interface OppNet extends OppNetEventsSource {

    public static final String NODE_ADDED = "na";
    public static final String NODE_REMOVED = "nd";
    public static final String NODE_MOVED = "nm";
    public static final String EDGE_ADDED = "ea";
    public static final String EDGE_REMOVED = "ed";
    public static final String EDGE_CHANGED = "ec";

    //----------------------------------------------------------------
    // Nodes
    //----------------------------------------------------------------
    /**
     * Add a new node in the OppNet.
     *
     * @param nodeId the new node id.
     * @param profile the node's profile name (may be null)
     */
    public void addNode(String nodeId, String profile);

    /**
     * Remove a node from the OppNet.
     *
     * @param nodeId the id of the node to be deleted.
     */
    public void deleteNode(String nodeId);

    /**
     * Check whether the node exists in the OppNet.
     *
     * @param nodeId a node id.
     * @return true if a node having this node id exists in the graph.
     */
    public boolean isNode(String nodeId);

    /**
     * Give the nodes in the OppNet.
     *
     * @return a collection of all nodes in the graph.
     */
    public Collection<String> getNodes();

    /**
     * Change the on/offline status of the node and update edges accordingly.
     *
     * @param nodeId a node id.
     * @param online the new status for the node having this id.
     */
    public void setOnline(String nodeId, boolean online);

    /**
     * Give the on/offline status of the node.
     *
     * @param nodeId a node id.
     * @return the status of the node having this id.
     */
    public boolean isOnline(String nodeId);

    /**
     * Give a tag to the node.
     *
     * @param nodeId a node id.
     * @param tag the new status for the node having this id.
     */
    public void setTag(String nodeId, String tag);

    /**
     * Give the tag of the node.
     *
     * @param nodeId a node id.
     * @return the tag of the node having this id.
     */
    public String getTag(String nodeId);

    /**
     * Add a new connectivity type for the node and update edges accordingly.
     *
     * @param nodeId a node id.
     * @param connectivityType a connectivity type to be added to this node.
     */
    public void addConnectivityType(String nodeId, String connectivityType);

    /**
     * Remove a connectivity type for the node and update edges accordingly.
     *
     * @param nodeId a node id.
     * @param connectivityType a connectivity type to be removed from this node.
     */
    public void removeConnectivityType(String nodeId, String connectivityType);

    /**
     * Change the status of a node for a given connectivity type.
     *
     * @param nodeId a node id.
     * @param connectivityType a connectivity type.
     * @param status the new status.
     */
    public void setNodeStatus(String nodeId,
            String connectivityType, String status);

    /**
     * Give the status of a node for a given connectivity type.
     *
     * @param nodeId a node id.
     * @param connectivityType a connectivity type.
     * @return the status for this node and connectivity type.
     */
    public String getNodeStatus(String nodeId, String connectivityType);

    //----------------------------------------------------------------
    // Connectivity
    //----------------------------------------------------------------
    /**
     * Change the status of an edge charaterized by the nodes' ids and the
     * connectivity type. If the edge does not exist, do nothing and change the
     * status of nodes accordingly.
     *
     * @param nodeId1 a node id.
     * @param nodeId2 another node id.
     * @param connectivityType a connectivity type.
     * @param status the new edge status.
     * @return true if the status has been changed.
     */
    public boolean setEdgeStatus(String nodeId1, String nodeId2,
            String connectivityType, String status);

    /**
     * Give the status of an edge charaterized by the nodes' ids and the
     * connectivity type. If the edge does not exist, return null
     *
     * @param nodeId1 a node id.
     * @param nodeId2 another node id.
     * @param connectivityType a connectivity type.
     * @return the edge status
     */
    public String getEdgeStatus(String nodeId1, String nodeId2,
            String connectivityType);

    /**
     * Give the neighbors' ids of the node for a given connectivity type and
     * status. If connectivityType is null, give all neighbors for any
     * connectivity type. If status is null, give all neighbors for any status.
     *
     * @param nodeId a node id.
     * @param connectivityType a connectivity type. May be null.
     * @param edgeStatus an edge status. May be null.
     * @return ids of nodes having edges with the given status and connectivity
     * type.
     */
    public Collection<String> getNeighbors(String nodeId,
            String connectivityType, String edgeStatus);

    /**
     * Returns true if there is an edge with the node for the given connectivity
     * type and status. If connectivityType is null, return true if there is an
     * edge for any connectivity type. If status is null, give all neighbors for
     * any status.
     *
     * @param nodeId1 a node id.
     * @param nodeId2 another node id.
     * @param connectivityType a connectivity type. May be null.
     * @param edgeStatus an edge status. May be null.
     * @return return true if the nodes have an edge having the given status and
     * connectivity type.
     */
    public boolean areNeighbors(String nodeId1, String nodeId2,
            String connectivityType, String edgeStatus);

    /**
     * Returns the number of neighbors of the node for the given
     * connectivity type and status. If connectivityType is null,
     * returns the number of neighbors for any connectivity type. If
     * status is null, returns the number of neighbors whatever the
     * connectivity status.
     *
     * @param nodeId a node id.
     * @param connectivityType a connectivity type. May be null.
     * @param edgeStatus an edge status. May be null.
     * @return return true if the nodes have an edge having the given status and
     * connectivity type.
     */
    public int nbNeighbors(String nodeId,
			   String connectivityType, String edgeStatus);
    
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
    public String makeEdgeId(String id1, String id2, String connectivityType);

}
