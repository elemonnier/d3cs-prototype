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
import casa.util.geom.CoordCar;
import java.util.Set;
import org.graphstream.graph.Node;
import org.graphstream.graph.implementations.AbstractEdge;

/**
 * A {@link org.graphstream.graph.Edge} for a
 *
 * {@link org.graphstream.graph.Graph} representing a potential/real connection
 * between two {@link OppNode} for a given connectivity type. The connection is
 * characterized by the distance between the devices, that must be lower than
 * the connectivity type's range.
 *
 */
public class OppEdge
        extends AbstractEdge {

    private long range;      // maximum range for the edge connectivity type
    private double distance; // distance between the nodes

    private String prevType;    // connectivity type printed to DGS previously
    private String prevStatus;  // status printed to DGS previously
    private String prevTag;     // edge tag printed to DGS previously
    private Set<String> hidden; // types/status to hide for edges

    private String connectivityType, status, tag;

    private final DGSAttributes edgeAttributes;

    /**
     * Constructs a new edge.
     *
     * @param id unique edge id.
     * @param source a node.
     * @param target other node.
     * @param connectivityType the connectivity type.
     * @param range
     * @param status the edges's initial status.
     * @param hidden
     * @param defaultConnectivityType
     * @param defaultEdgeStatus
     */
    protected OppEdge(String id, OppNode source, OppNode target,
            String connectivityType, long range, String status, Set<String> hidden,
            String defaultConnectivityType, String defaultEdgeStatus) {
        super(id, source, target, false);
        this.edgeAttributes = new DGSAttributes(this);

        this.connectivityType = connectivityType;
        this.range = range;
        this.status = status;
        this.hidden = hidden;
        updateDistance();
    }

    /**
     * Attributes initializations. Must be invoked after
     * {@link OppNetGraph#addEdge(String, Node, Node)}
     */
    public void init() {
        if (connectivityType != null) {
            setAttribute("type", connectivityType);
        }
        if (status != null) {
            setAttribute("status", status);
        }
        setUIattribute();
        addAttribute("layout.weight", 100);
        this.prevType = edgeAttributes.toString("type");
        this.prevStatus = edgeAttributes.toString("status");
    }

    /**
     * Gives a string representation of the edge to be printed to a DGS output.
     * @param withNodes if true, add the nodes ids after the edge id (for the edge creation)
     * @return DGS sring representation of the edge
     */
    public String toDGS(boolean withNodes) {
        StringBuilder toDGS = new StringBuilder(getId());
        if (withNodes) {
            toDGS.append(' ').append(getSourceNode().getId());
            toDGS.append(' ').append(getTargetNode().getId());
        }
        prevType = addToDgs(toDGS, edgeAttributes.toString("type"), prevType);
        prevStatus = addToDgs(toDGS, edgeAttributes.toString("status"), prevStatus);
        prevTag = addToDgs(toDGS, "tag", edgeAttributes.toString("tag"), prevTag);
        return toDGS.toString();
    }

    private String addToDgs(StringBuilder builder, String key, String newStr, String prevStr) {
        if (newStr.equals("") && prevStr != null) {
            builder.append(" -").append(key);
            return null;
        }
        return addToDgs(builder, newStr, prevStr);
    }

    private String addToDgs(StringBuilder builder, String newStr, String prevStr) {
        if (newStr.length() > 0 && (prevStr == null || !prevStr.equals(newStr))) {
            builder.append(' ').append(newStr);
            return newStr;
        }
        return prevStr;
    }

    @Override
    protected void attributeChanged(AttributeChangeEvent event, String attribute, Object oldValue, Object newValue) {
        super.attributeChanged(event, attribute, oldValue, newValue); // TODO NoSuchElementException here
        if (attribute.equals("type") || attribute.equals("status") || attribute.equals("tag")) {
            setUIattribute();
        }
    }

    /**
     * Set the "ui.hide" and "ui.class" attributes of the edge according to its
     * type and status.
     */
    void setUIattribute() {
        String type = getConnectivityType();
        String status = getStatus();
        String value = type;
        if (status != null) {
            value = (value == null ? status : value + "," + status);
        }
        if (tag != null) {
            value = (value == null ? status : value + "," + tag);
        }
        if (hidden != null
                && ((status != null && hidden.contains(status))
                || (type != null && hidden.contains(type)))) {
            addAttribute("ui.hide");
        } else {
            removeAttribute("ui.hide");
        }
        if (value != null) {
            setAttribute("ui.class", value);
        }
    }

    //----------------------------------------------------------------
    // Attributes getters
    //----------------------------------------------------------------
    /**
     * Give the distance between the nodes computed by the previous
     * {@link #updateDistance()} invocation.
     */
    public double getDistance() {
        return distance;
    }

    /**
     * Give the edge connectivity type.
     */
    public String getConnectivityType() {
        return connectivityType;
    }

    /**
     * Return the edge's status.
     */
    public String getStatus() {
        return status;
    }

    //----------------------------------------------------------------
    // Attributes setters
    //----------------------------------------------------------------
    /**
     * Update the edge's distance from the nodes locations.
     */
    public void updateDistance() {
        CoordCar sourceCoord = ((OppNode) getSourceNode()).getCoord();
        CoordCar targetCoord = ((OppNode) getTargetNode()).getCoord();
        if (sourceCoord != null && targetCoord != null) {
            distance = sourceCoord.distanceTo(targetCoord);
        }
    }

    /**
     * Returns true if the two nodes are within mutual radio range for its
     * connectivity type.
     */
    public boolean isInRange() {
        return distance <= range;
    }

    /**
     * Update the connected status of the nodes.
     */
    public boolean setStatus(String status) {
        if (status == null) {
            return false;
        }
        String oldStatus = getStatus();
        if (oldStatus != null && oldStatus.equals(status)) {
            return false;
        }

        this.status = status;
        setAttribute("status", status);
        return true;
    }

    /**
     * Update the edge connectivity type.
     */
    public boolean setConnectivityType(String connectivityType) {
        if (connectivityType == null) {
            return false;
        }
        String oldType = getConnectivityType();
        if (oldType != null && oldType.equals(connectivityType)) {
            return false;
        }

        this.connectivityType = connectivityType;
        setAttribute("type", connectivityType);
        return true;
    }

    //----------------------------------------------------------------
    // Tag
    //----------------------------------------------------------------
    public boolean isTagged() {
        return tag != null;
    }

    public String getTag() {
        return tag;
    }

    public void setTag(String tag) {
        if (tag != null) {
            setAttribute("tag", tag);
        } else if (this.tag != null) {
            removeAttribute("tag");
        }
        this.tag = tag;
        setUIattribute();
    }

}
