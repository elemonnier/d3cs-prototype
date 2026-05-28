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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * A fully connected opportunistic network: all pairs of nodes are linked
 * together, provided both nodes are online.
 *
 */
public class OppNetFullyConnected implements OppNet {

    private final Map<String, Node> nodes;
    private final Map<String, Edge> edges;

    public OppNetFullyConnected() {
        nodes = new HashMap<>();
        edges = new HashMap<>();
    }

    @Override
    public void addNode(String nodeId, String profile) {
        if (!nodes.containsKey(nodeId)) {
            nodes.put(nodeId, new Node(nodeId, profile));
        }
    }

    @Override
    public void deleteNode(String nodeId) {
        nodes.remove(nodeId);
    }

    @Override
    public boolean isNode(String nodeId) {
        return nodes.containsKey(nodeId);
    }

    @Override
    public Collection<String> getNodes() {
        return nodes.keySet();
    }

    @Override
    public void setOnline(String nodeId, boolean online) {
        Node node = nodes.get(nodeId);
        if (node != null) {
            node.online = online;
        }
    }

    @Override
    public boolean isOnline(String nodeId) {
        Node node = nodes.get(nodeId);
        if (node != null) {
            return node.online;
        }
        return false;
    }

    @Override
    public void setTag(String nodeId, String tag) {
        Node node = nodes.get(nodeId);
        if (node != null) {
            node.tag = tag;
        }
    }

    @Override
    public String getTag(String nodeId) {
        Node node = nodes.get(nodeId);
        if (node != null) {
            return node.tag;
        }
        return null;
    }

    @Override
    public void addConnectivityType(String nodeId, String connectivityType) {
        Node node = nodes.get(nodeId);
        if (node != null) {
            node.connectivityTypes.add(connectivityType);
        }
    }

    @Override
    public void removeConnectivityType(String nodeId, String connectivityType) {
        Node node = nodes.get(nodeId);
        if (node != null) {
            node.connectivityTypes.remove(connectivityType);
        }
    }

    @Override
    public void setNodeStatus(String nodeId, String connectivityType, String status) {
        Node node = nodes.get(nodeId);
        if (node != null && node.connectivityTypes.contains(connectivityType)) {
            node.status.put(connectivityType, status);
        }
    }

    @Override
    public String getNodeStatus(String nodeId, String connectivityType) {
        Node node = nodes.get(nodeId);
        if (node != null && node.connectivityTypes.contains(connectivityType)) {
            return node.status.get(connectivityType);
        }
        return null; // TODO return default status?
    }

    @Override
    public boolean setEdgeStatus(String nodeId1, String nodeId2, String connectivityType, String status) {
        String edgeId = makeEdgeId(nodeId1, nodeId2, connectivityType);
        Edge edge = edges.get(edgeId);
        if (edge != null) {
            edge.status = status;
        } else {
            edges.put(edgeId, new Edge(edgeId, connectivityType, status));
        }
        return true;
    }

    @Override
    public String getEdgeStatus(String nodeId1, String nodeId2, String connectivityType) {
        String edgeId = makeEdgeId(nodeId1, nodeId2, connectivityType);
        Edge edge = edges.get(edgeId);
        if (edge != null) {
            return edge.status;
        }
        return null;
    }

    @Override
    public Collection<String> getNeighbors(String nodeId, String connectivityType, String edgeStatus) {
        Node node = nodes.get(nodeId);
        Set<String> neighbors = new HashSet<>();
        if (node != null) {
            if (connectivityType == null || node.connectivityTypes.contains(connectivityType)) {
                for (Node n : nodes.values()) {
                    if (!n.id.equals(nodeId) && n.online) {
                        if (connectivityType == null && edgeStatus == null) {
                            neighbors.add(n.id);
                        } else if (connectivityType != null && n.connectivityTypes.contains(connectivityType)) {
                            if (edgeStatus == null) {
                                neighbors.add(n.id);
                            } else {
                                Edge edge = edges.get(makeEdgeId(nodeId, n.id, connectivityType));
                                if (edge != null && edgeStatus.equals(edge.status)) {
                                    neighbors.add(n.id);
                                }
                            }
                        }
                    }
                }
            }
        }
        return neighbors;
    }

    @Override
    public int nbNeighbors(String nodeId, String connectivityType, String edgeStatus) {
	Collection<String> neighbors = getNeighbors(nodeId, connectivityType,
						    edgeStatus);
	if (neighbors == null)
	    return 0;
	else
	    return neighbors.size();
    }
    
    @Override
    public boolean areNeighbors(String nodeId1, String nodeId2, String connectivityType, String edgeStatus) {
        Node node1 = nodes.get(nodeId1);
        Node node2 = nodes.get(nodeId2);
        if (node1 != null && node2 != null && node1.online && node2.online) {
            if (connectivityType == null && edgeStatus == null) {
                return true;
            } else if (connectivityType != null && node1.connectivityTypes.contains(connectivityType) && node2.connectivityTypes.contains(connectivityType)) {
                if (edgeStatus == null) {
                    return true;
                } else {
                    Edge edge = edges.get(makeEdgeId(nodeId1, nodeId2, connectivityType));
                    return edgeStatus.equals(edge.status);
                }
            }
        }
        return false;
    }

    @Override
    public String makeEdgeId(String node1, String node2, String connectivityType) {
        if (node1.compareTo(node2) < 0) {
            return node1 + "-" + node2 + "-" + connectivityType;
        } else {
            return node2 + "-" + node1 + "-" + connectivityType;
        }
    }

    @Override
    public void addEdgeListener(String nodeId, String connectivityType, OppEdgeListener listener) {
        // TODO FullConnectivityOppNet#addEdgeListener
    }

    @Override
    public void removeEdgeListener(String nodeId, String connectivityType) {
        // TODO FullConnectivityOppNet#removeEdgeListener
    }

    @Override
    public void addNodeListener(String nodeId, OppNodeListener listener) {
        // TODO FullConnectivityOppNet#addNodeListener
    }

    @Override
    public void removeNodeListener(String nodeId) {
        // TODO FullConnectivityOppNet#removeNodeListener
    }

    class Node {

        final String id;
        String profile, tag;
        boolean online;
        final Set<String> connectivityTypes;
        final Map<String, String> status;

        public Node(String id, String profile) {
            this.id = id;
            this.profile = profile;
            this.connectivityTypes = new HashSet<>();
            this.status = new HashMap<>();
        }

    }

    class Edge {

        final String id, connectivityType;
        String status;

        public Edge(String id, String connectivityType, String status) {
            this.id = id;
            this.connectivityType = connectivityType;
            this.status = status;
        }
    }
}
