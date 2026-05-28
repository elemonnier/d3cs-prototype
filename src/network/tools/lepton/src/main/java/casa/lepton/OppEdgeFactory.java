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

import casa.lepton.conf.ConnectivityProfiles;
import casa.lepton.conf.OppNetProperties;
import java.util.HashSet;
import java.util.Set;
import org.graphstream.graph.EdgeFactory;
import org.graphstream.graph.Graph;
import org.graphstream.graph.Node;

/**
 * Class used to dynamically create {@link OppEdge} instances. The
 * {@link #newInstance(String, Node, Node, boolean) } method is called by the
 * {@link Graph#addEdge(String, Node, Node)} method.
 *
 * Setters ({@link #setConnectivityType(String)}, {@link #setStatus(String)})
 * allow to set the edge properties for subsequent creations
 *
 */
public class OppEdgeFactory implements EdgeFactory<OppEdge> {

    private String defaultConnectivityType; // the default edge connectivity type
    private String defaultStatus;           // the default edge status
    private String connectivityType;        // connectivity type for object creations
    private String status;                  // status for object creations
    private long range;
    private Set<String> hidden = new HashSet<>(); // types/status to hide for edges
    private final ConnectivityProfiles connectivityProfiles;
    private final OppNetRules oppNetRules;

    //-------------------------------------------------------------------------
    /**
     * Constructor.
     *
     * @param props the default edge properties
     */
    public OppEdgeFactory(OppNetProperties props) {
        this.defaultConnectivityType = props.getDefaultConnectivityType();
        this.defaultStatus = props.getEdgeDefaultStatus();
        setConnectivityType(defaultConnectivityType);
        setStatus(defaultStatus);
        this.connectivityProfiles = props.getConnectivityProfiles();
        this.hidden = props.getHiddenEdges();
        this.oppNetRules = props.getOppNetRules();
    }

    //-------------------------------------------------------------------------
    /**
     * Create a {@link OppEdge} instance.
     *
     * @param id unique edge id.
     * @param src the source node.
     * @param dst the target node.
     * @param directed not used.
     * @return the new edge
     */
    @Override
    public OppEdge newInstance(String id, Node src, Node dst, boolean directed) {
        OppNode source = (OppNode) src;
        OppNode target = (OppNode) dst;
        String edgeStatus = this.status;
        return new OppEdge(id, source, target, connectivityType, range, edgeStatus, hidden, defaultConnectivityType, defaultStatus);
    }

    //-------------------------------------------------------------------------
    // Setters of the attributes for the subsequent edge creations
    //-------------------------------------------------------------------------
    /**
     * Set the connectivity type for the subsequent object creations.
     *
     * @param connectivityType
     */
    public void setConnectivityType(String connectivityType) {
        if (connectivityType != null) {
            this.connectivityType = connectivityType;
        }
    }

    //-------------------------------------------------------------------------
    /**
     * Set the edge status for the subsequent object creations.
     *
     * @param status
     */
    public void setStatus(String status) {
        if (status != null) {
            this.status = status;
            if (connectivityProfiles != null) {
                this.range = connectivityProfiles.getRange(status);
            }
        }
    }

    //-------------------------------------------------------------------------
    // Private methods
    //-------------------------------------------------------------------------
    /**
     * Give a unique edge id from the given nodes ids and connectivityType in
     * the form "id1-id2:type" where id1 < id2.
     *
     * @param src a node.
     * @param dst other node.
     * @param connectivityType the connectivity type.
     * @return unique edge id.
     */
    public String makeEdgeId(Node src, Node dst, String connectivityType) {
        String id1 = src.getId();
        String id2 = dst.getId();
        return makeEdgeId(id1, id2, connectivityType);
    }

    //-------------------------------------------------------------------------
    /**
     * Give a unique edge id from the given nodes ids and connectivityType in
     * the form "id1-id2:type" where id1 < id2.
     *
     * @param id1 a node id.
     * @param id2 other node id.
     * @param connectivityType the connectivity type.
     * @return unique edge id.
     */
    public String makeEdgeId(String id1, String id2, String connectivityType) {
        if (id1.compareTo(id2) > 0) {
            String tmp = id1;
            id1 = id2;
            id2 = tmp;
        }
        if (connectivityType == null || (defaultConnectivityType != null && connectivityType.equals(defaultConnectivityType))) {
            return id1 + "-" + id2;
        }
        return id1 + "-" + id2 + "-" + connectivityType;
    }
}
