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
import casa.lepton.conf.OppNodeProperties;
import casa.lepton.walk.Walker;
import casa.util.geom.CoordCar;
import casa.util.geom.CoordGeo;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.NumberFormat;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.graphstream.graph.implementations.MultiNode;

/**
 * A {@link org.graphstream.graph.Node} representing a device in an
 * opprotunistic network. The device has a location, can be on/offline, and has
 * several connectivity types. For each connectivity type, it can have edges
 * with other nodes that are within a range defined for this connectivity type.
 *
 */
public class OppNode
        extends MultiNode {

    private static final NumberFormat F1 = NumberFormat.getNumberInstance(Locale.US);

    static {
        F1.setMinimumFractionDigits(2);
        F1.setMaximumFractionDigits(2);
        F1.setGroupingUsed(false);
    }

    private CoordCar coordInit;                        // the device's location
    private String defaultStatus;                      // the node initial default status for any connectivity type
    private CoordGeo refLocation;                      // the geographical reference location

    private Walker walker;                             // implements the node's mobility
    private String showStatus;                         // connectivity type for which node status is shown

    // the node attributes (set with the {@link Element#addAttribute(String, Object...)} method)
    private CoordCar coord;                            // the node's location
    private boolean mobile = true;                     // true if the node's location can change
    private boolean online = true;                     // true if the node is online. If not, the node cannot "communicate" (has no edges)
    private Collection<String> supportedTypes;         // supported connectivity types
    private Map<String, String> status;                // status for each connectivity type
    private String label;                              // the node label
    private String tag;                                // a tag (may be null)

    // String representations of attributes printed to the DGS output. They are stored
    // in order to avoid to write all attributes at each modification in one attribute
    private String prevLabel;                  // label printed to DGS previously
    private String prevLocation;               // location printed to DGS previously
    private String prevStatus;                 // status printed to DGS previously
    private String prevOnline;                 // online status printed to DGS previously
    private String prevMobile;                 // mobile status printed to DGS previously
    private String prevProfile;                // node profile printed to DGS previously
    private String prevTag;                    // node tag printed to DGS previously

    private boolean statusAttributeCoherent;   // true if the status map and "status" attribute are coherent

    private final DGSAttributes nodeAttributes;

    private static final Path D3CS_USERS_DIR = resolveD3csUsersDir();

    /**
     * Construct a new node.
     *
     * @param graph the graph representing the network.
     * @param id the node id (unique).
     * @param profile the profile name
     * @param props the properties
     * @param walker the walker that implements the node mobility
     */
    public OppNode(OppNetGraph graph, String id, String profile, OppNodeProperties props, String label, Walker walker) {
        this(graph, id, profile, props, label);
        this.walker = walker;
    }

    /**
     * Construct a new node.
     *
     * @param graph the graph representing the network.
     * @param id the node id (unique).
     * @param profile the profile name
     * @param props the properties
     * @param coord the node initial location
     */
    public OppNode(OppNetGraph graph, String id, String profile, OppNodeProperties props, String label, CoordCar coord) {
        this(graph, id, profile, props, label);
        this.coordInit = coord;
    }

    /**
     * Construct a new node.
     *
     * @param graph the graph representing the network.
     * @param id the node id (unique).
     * @param profile the profile name
     * @param props the properties
     */
    private OppNode(OppNetGraph graph, String id, String profile, OppNodeProperties props, String label) {
        super(graph, id);
        this.nodeAttributes = new DGSAttributes(this);

        setMobile(props.isMobile());
        setOnline(true);
        if (profile != null) {
            setAttribute("profile", profile);
        }

        this.supportedTypes = props.getSupportedConnectivityTypes();
        this.defaultStatus = props.getNodeDefaultStatus();
        this.status = new HashMap<>();
        for (String type : supportedTypes) {
            status.put(type, defaultStatus);
        }
        this.showStatus = props.getShowNodeStatus();
        setAttribute("status", toString(this.status));

        setLabel(label);

        setTag(props.getTag());

        // the default initial values that should not be printed to the DGS
        this.prevOnline = nodeAttributes.toString("online");
        this.prevMobile = nodeAttributes.toString("mobile");
        this.prevStatus = nodeAttributes.toString("status");
    }

    /**
     * Attributes initializations. Must be invoked after
     * {@link OppNetGraph#addNode(java.lang.String, java.lang.String)}
     */
    public void init() {
        long now = ((OppNetGraph) graph).getCurrentStep();
        if (walker != null) {
            setCoord(walker.getPosition(now));
        } else if (coordInit != null) {
            setCoord(coordInit);
        }
        setOnline(true);
        setUIattribute();
        addAttribute("layout.weight", 10000);
    }

    //----------------------------------------------------------------
    // toDGS
    //----------------------------------------------------------------
    /**
     * Gives a string representation of the node to be printed to a DGS output.
     *
     * @return DGS sring representation of the node
     */
    public String toDGS() {
        StringBuilder toDGS = new StringBuilder(getId());
        prevProfile = addToDgs(toDGS, nodeAttributes.toString("profile"), prevProfile);
        prevLocation = addToDgs(toDGS, locationToString(), prevLocation);
        prevStatus = addToDgs(toDGS, nodeAttributes.toString("status"), prevStatus);
        prevOnline = addToDgs(toDGS, nodeAttributes.toString("online"), prevOnline);
        prevMobile = addToDgs(toDGS, nodeAttributes.toString("mobile"), prevMobile);
        prevLabel = addToDgs(toDGS, "label", nodeAttributes.toString("label"), prevLabel);
        prevTag = addToDgs(toDGS, "tag", nodeAttributes.toString("tag"), prevTag);
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

    /*
     * Gives a string representation of the node's location.
     */
    private String locationToString() {
        if (coord == null) {
            return "";
        }
        return "x=" + F1.format(coord.x)
                + " y=" + F1.format(coord.y);
    }

    //----------------------------------------------------------------
    // Label
    //----------------------------------------------------------------
    public String getLabel() {
        return label != null ? label : id;
    }

    public final void setLabel(String label) {
        if (label != null && !label.equals(id)) {
            this.label = label;
            setAttribute("label", label);
        } else if (this.label != null) {
            this.label = null;
            removeAttribute("label");
        }
        setUIattribute();
    }

    @Override
    public String toString() {
        return getLabel();
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

    public final void setTag(String tag) {
        if (tag != null) {
            setAttribute("tag", tag);
        } else if (this.tag != null) {
            removeAttribute("tag");
        }
        this.tag = tag;
        setUIattribute();
    }

    //----------------------------------------------------------------
    // Mobility
    //----------------------------------------------------------------
    public final void setMobile(boolean mobile) {
        this.mobile = mobile;
        setAttribute("mobile", mobile);
    }

    public boolean isMobile() {
        return this.mobile;
    }

    //----------------------------------------------------------------
    // Neighbors
    //----------------------------------------------------------------
    /**
     * Give all the node's neighbors for a given connectivity type and a given
     * status. If connectivityType is null, give all neighbors for any
     * connectivity type. If status is null, give all neighbors for any status.
     *
     * @param connectivityType the connectivity type (may be null).
     * @param edgeStatus the status (may be null).
     * @return neighbors
     */
    public synchronized Collection<OppNode> getNeighbors(String connectivityType,
            String edgeStatus) {
        Collection<OppNode> neighbors = new HashSet<>();

        Set<OppNode> allNeighbors = new HashSet<>();
        Collection<OppEdge> allEdges = super.getEdgeSet();
        for (OppEdge edge : allEdges) {
            OppNode node = edge.getOpposite(this);
            allNeighbors.add(node);
        }
        for (OppNode node : allNeighbors) {
            boolean isNeighbor = true;

            if (this.equals(node)) {
                isNeighbor = false;

            } else if (connectivityType != null || edgeStatus != null) {
                isNeighbor = false;
                Collection<OppEdge> edges = getEdgeSetBetween(node);
                Iterator<OppEdge> itEdges = edges.iterator();
                while (!isNeighbor && itEdges.hasNext()) {
                    OppEdge edge = itEdges.next();
                    isNeighbor = filter(edge, connectivityType, edgeStatus);
                    // exit when matching edge found
                }
            }
            // else no need to check edges

            if (isNeighbor) {
                neighbors.add(node);
            }
        }
        return neighbors;
    }

    /**
     * Returns true if there is an edge with the node for the given connectivity
     * type and status. If connectivityType is null, return true if there is an
     * edge for any connectivity type. If status is null, give all neighbors for
     * any status.
     *
     * @param node a node.
     * @param connectivityType the connectivity type (may be null).
     * @param edgeStatus the status (may be null).
     * @return true if the given node is a neighbor
     */
    public boolean isNeighbor(OppNode node,
            String connectivityType, String edgeStatus) {
        if (this.equals(node)) {
            return false;
        }

        Collection<OppEdge> edges = getEdgeSetBetween(node);
        if (edges == null || edges.isEmpty()) {
            return false;
        }

        if (connectivityType == null && edgeStatus == null) {
            return true;
        }

        for (OppEdge edge : edges) {
            if (filter(edge, connectivityType, edgeStatus)) {
                return true;
            }
        }

        return false;
    }

    /*
     * Check whether the given edge matches the given properties:
     * same connectivityType or any if given connectivityType is null
     * and same status or any if given status is null
     */
    private boolean filter(OppEdge edge,
            String connectivityType, String edgeStatus) {
        if (connectivityType != null
                && !connectivityType.equals(edge.getConnectivityType())) {
            return false;
        }
        if (edgeStatus != null
                && !edgeStatus.equals(edge.getStatus())) {
            return false;
        }
        return true;
    }

    //----------------------------------------------------------------
    // Attributes setters
    //----------------------------------------------------------------
    /**
     * Change the on/offline status of the device.
     *
     * @param online the new status value.
     * @return true if the status has changed.
     */
    public final boolean setOnline(boolean online) {
        if (this.online != online) {
            this.online = online;
            setAttribute("online", online);
            setUIattribute();
            return true;
        }
        return false;
    }

    /**
     * Add a new enabled connectivity type.
     *
     * @param connectivityType the new connectivity type.
     * @return true if the types have changed.
     */
    public boolean addConnectivityType(String connectivityType) {
        if (supportedTypes.contains(connectivityType)) {
            return false;
        }

        supportedTypes.add(connectivityType);
        status.put(connectivityType, defaultStatus);
        return true;
    }

    /**
     * Disable a connectivity type.
     *
     * @param connectivityType the connectivity type.
     * @return true if the types have changed.
     */
    public boolean removeConnectivityType(String connectivityType) {
        if (!supportedTypes.contains(connectivityType)) {
            return false;
        }

        supportedTypes.remove(connectivityType);
        return true;
    }

    /**
     * Change the device's location and update its edges distances using
     * {@link OppEdge#updateDistance()}.
     *
     * @param time the time when the device's location must be changed.
     * @return true if the device's location has changed.
     */
    public boolean walk(long time) {
        if (!mobile || walker == null) {
            return false;
        }

        CoordCar coord = walker.getPosition(time);
        if (coord == null) {
            setOnline(false);
            if (this.coord == null) {
                return false;
            }
        } else if (this.coord == null) {
            setOnline(true);
        } else if (this.coord.equals(coord)) {
            return false;
        }
        setCoord(coord);
        return true;
    }

    /**
     * Change the coord attribute.
     *
     * @param coord the new coord attribute.
     */
    public void setCoord(CoordCar coord) {
        this.coord = coord;
        if (coord != null) {
            DGSAttributes graphAttributes = getGraph().getAttributes();
            if (graphAttributes.has("latRef") && graphAttributes.has("lonRef")) {
                double lat = graphAttributes.getDouble("latRef", 0);
                double lon = graphAttributes.getDouble("lonRef", 0);
                this.refLocation = new CoordGeo(lat, lon);
            }
            this.setAttribute("xy", coord.x, coord.y);

            // update the edges distances
            Collection<OppEdge> edges = getEdgeSet();
            for (OppEdge edge : edges) {
                edge.updateDistance();
            }
        } else {
            this.removeAttribute("xy");
        }
    }

    /**
     * Update the status of the node for a given type.
     *
     * @param connectivityType the connectivity type.
     * @param status the new status.
     * @return true if the status has been changed.
     */
    public boolean setStatus(String connectivityType, String status) {
        if (status == null) {
            return false;
        }
        String st = this.status.get(connectivityType);
        if (st != null && st.equals(status)) {
            return false;
        }

        this.status.put(connectivityType, status);
        statusAttributeCoherent = true; // to avoid attributeChanged to compute again status
        setAttribute("status", toString(this.status));
        return true;
    }

    //----------------------------------------------------------------
    // Attributes getters
    //----------------------------------------------------------------
    /**
     * Give the on/offline status of the device.
     *
     * @return true if the status is online.
     */
    public boolean isOnline() {
        return this.online;
    }

    /**
     * Return true if the device has the given connectivity type.
     *
     * @param connectivityType a connectivity type
     * @return true if the device has the given connectivity type.
     */
    public boolean hasConnectivityType(String connectivityType) {
        return supportedTypes.contains(connectivityType);
    }

    /**
     * Return the device's enabled connectivity types.
     *
     * @return a collection of the device's enabled connectivity types.
     */
    public Collection<String> getConnectivityTypes() {
        return supportedTypes;
    }

    /**
     * Give the device location.
     *
     * @return the device location.
     */
    public CoordCar getCoord() {
        return coord;
    }

    /**
     * Return the node's status for a given connectivity type.
     *
     * @param connectivityType a connectivity type
     * @return the node's status for this connectivity type.
     */
    public String getStatus(String connectivityType) {
        if (connectivityType != null) {
            return this.status.get(connectivityType);
        }
        return null;
    }

    @Override
    public OppNetGraph getGraph() {
        return (OppNetGraph) super.getGraph();
    }

    //----------------------------------------------------------------
    // UIAttributes
    //----------------------------------------------------------------
    @Override
    protected void attributeChanged(AttributeChangeEvent event, String attribute, Object oldValue, Object newValue) {
        super.attributeChanged(event, attribute, oldValue, newValue);
        if (attribute.equals("status")) {
            if (!statusAttributeCoherent) // i.e. event fired by setStatus
            {
                this.status = parseMap(newValue);
            }
            setUIattribute();
            statusAttributeCoherent = false;
        }
    }

    /**
     * Set the "ui.class" attribute of the node according to the given type,
     * node status and tag, and the "ui.label" attribute according to the label
     * or id (if label is null)
     */
    void setUIattribute() {
        // online/offline status
        String value = isOnline() ? "ONLINE" : "OFFLINE";

        // status for the 'showStatus' connectivity type
        String status = getStatus(showStatus);
        if (status != null && !status.equals("")) {
            value += ", " + status;
        }

        // tag
        if (tag != null && !tag.equals("")) {
            value += ", " + tag;
        }
        setAttribute("ui.class", value);
        setAttribute("ui.label", displayLabel());
    }

    public void refreshDynamicLabel() {
        setAttribute("ui.label", displayLabel());
    }

    private String displayLabel() {
        String display = label == null ? id : label;
        String userNode = d3csUserNode(display);
        if (userNode == null) {
            return display;
        }
        String status = keyStatus(userNode);
        if (status.isEmpty()) {
            return display;
        }
        return display.endsWith("|") ? display + status : display + "|" + status;
    }

    private String d3csUserNode(String display) {
        int idx = display.indexOf('|');
        String candidate = idx >= 0 ? display.substring(0, idx) : display;
        return candidate.matches("(?i)U[0-9]+") ? candidate : null;
    }

    private String keyStatus(String userNode) {
        String login = userNode.toLowerCase(Locale.US);
        boolean hasAbe = fileHasContent(D3CS_USERS_DIR.resolve(login).resolve("psks" + login + ".bin"));
        boolean hasAbs = fileHasContent(D3CS_USERS_DIR.resolve(login).resolve("skw" + login + ".bin"));
        if (hasAbe && hasAbs) {
            return "ABE+ABS";
        }
        if (hasAbe) {
            return "ABE";
        }
        return "";
    }

    private boolean fileHasContent(Path path) {
        try {
            return Files.isRegularFile(path) && Files.size(path) > 0;
        } catch (Exception ex) {
            return false;
        }
    }

    private static Path resolveD3csUsersDir() {
        String configured = System.getProperty("D3CS_USERS_DIR");
        if (configured == null || configured.trim().isEmpty()) {
            configured = System.getenv("D3CS_USERS_DIR");
        }
        if (configured != null && !configured.trim().isEmpty()) {
            Path path = Paths.get(configured);
            if (!path.isAbsolute()) {
                path = Paths.get(System.getProperty("user.dir")).resolve(path);
            }
            return path.normalize();
        }

        Path cwd = Paths.get(System.getProperty("user.dir"));
        Path repoRelative = cwd.resolve("../../../../runtime/users").normalize();
        if (Files.isDirectory(repoRelative)) {
            return repoRelative;
        }
        return cwd.resolve("runtime/users").normalize();
    }

    /*
     * Gives a string representation of a map.
     */
    private String toString(Map<String, String> map) {
        StringBuilder buffer = new StringBuilder("[");
        Iterator<String> it = map.keySet().iterator();
        if (it.hasNext()) {
            String key = it.next();
            buffer.append(key).append('=').append(map.get(key));
        }
        while (it.hasNext()) {
            String key = it.next();
            buffer.append(',').append(key).append('=').append(map.get(key));
        }
        buffer.append(']');
        return buffer.toString();
    }

    private Map<String, String> parseMap(Object obj) {
        if (obj instanceof String) {
            String str = (String) obj;
            Map<String, String> map = new HashMap<String, String>();
            if ((str.startsWith("[") && str.endsWith("]"))
                    || (str.startsWith("{") && str.endsWith("}"))) {
                String[] pairs = str.substring(1, str.length() - 1).split(",");
                for (String pair : pairs) {
                    String[] elts = pair.trim().split("=");
                    if (elts.length == 2) {
                        map.put(elts[0], elts[1]);
                    }
                }
            }
            return map;
        } else if (obj instanceof Map) {
            return (Map<String, String>) obj;
        }
        return new HashMap<String, String>();
    }
}
