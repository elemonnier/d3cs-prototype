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
package casa.lepton.ui;

import casa.lepton.OppEdge;
import casa.lepton.OppNetGraph;
import casa.lepton.OppNode;
import casa.util.geom.CoordCar;
import casa.util.geom.Segment;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.Point;
import java.awt.Stroke;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.util.Collection;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.graphstream.ui.graphicGraph.GraphicElement;
import org.graphstream.ui.graphicGraph.GraphicGraph;
import org.graphstream.ui.swingViewer.DefaultView;
import org.graphstream.ui.swingViewer.LayerRenderer;
import org.graphstream.ui.swingViewer.ViewPanel;

/**
 * Class used in "manual mode" (ie when no IN_DGS nor WALK_CLASS is supplied) to
 * allow to add and delete edges "manually".
 *
 * An edge is added by dragging from a source node to a target node. An edge is
 * removed by selected it and then pressing the 'delete' key.
 *
 */
public class EdgeDrawer implements KeyListener, MouseListener, MouseMotionListener, LayerRenderer {

    private static final int MARGIN = 18;

    private OppNode selectedNode;        // the node currently selected while drawing an edge
    private OppEdge selectedEdge;        // the edge currently selected in order to delete it

    private CoordCar dragStartPoint;     // the location where the drag started
    private Point dragCurrentPoint;      // the current location of the mouse while dragging

    private final ViewPanel graphPanel;
    private final OppNetFrame frame;
    private final OppNetGraph graph;

    private boolean enabled;

    public EdgeDrawer(OppNetFrame frame) {
        this.frame = frame;
        this.graph = frame.GetOppNetGraph();
        this.graphPanel = frame.getGraphPanel();
    }

    /**
     * Enable or disable the ability to draw or delete edges
     *
     * @param enable true if this object must be enabled
     */
    public void enable(boolean enable) {
        if (enable != enabled) {
            enabled = enable;
            if (enable) {
                graphPanel.addMouseMotionListener(this);
                graphPanel.addMouseListener(this);
                graphPanel.addKeyListener(this);
                if (graphPanel instanceof DefaultView) {
                    ((DefaultView) graphPanel).setForeLayoutRenderer(this);
                }
            } else {
                graphPanel.removeMouseMotionListener(this);
                graphPanel.removeMouseListener(this);
                graphPanel.removeKeyListener(this);
                if (graphPanel instanceof DefaultView) {
                    ((DefaultView) graphPanel).setForeLayoutRenderer(null);
                }
            }
        }
    }

    //-------------------------------------------------------------------------
    // MouseListener methods
    //-------------------------------------------------------------------------
    /**
     * Select and/or unselect an edge
     *
     * @param me the mouse event
     */
    @Override
    public void mouseClicked(MouseEvent me) {

        // unselect the previous selected edge if any
        OppEdge prevEdge = unselectEdge();

        // find the edge clicked if any
        Edge edge = getEdge(me.getPoint());

        if (edge != null && prevEdge != edge) {
            // select the edge
            OppEdge oppEdge = (OppEdge) edge;
            oppEdge.setTag("TAG");
            selectedEdge = oppEdge;
        }
    }

    /**
     * Initialize dragging if the mouse is pressed on a node
     *
     * @param me the mouse event
     */
    @Override
    public void mousePressed(MouseEvent me) {

        // find the node if any
        Node node = getNode(me.getPoint());

        if (node != null) {
            // select the node and initialize dragging
            selectedNode = (OppNode) node;
            selectedNode.setTag("TAG");
            dragStartPoint = frame.getCoord(selectedNode);
            dragCurrentPoint = null;
        }
    }

    /**
     * Add an edge if dragging ends on a node
     *
     * @param me the mouse event
     */
    @Override
    public void mouseReleased(MouseEvent me) {

        if (selectedNode != null) {

            // find the node if any
            Node node = getNode(me.getPoint());

            // add a new edge
            if (node != null && node != selectedNode) {
                String nodeId0 = selectedNode.getId();
                String nodeId1 = node.getId();
                String type = (nodeId0.compareTo(nodeId1) < 0 ? 
                        getCommonType(selectedNode, (OppNode)node) : 
                        getCommonType((OppNode)node, selectedNode));
                String edgeId = graph.makeEdgeId(nodeId0, nodeId1, type); 
                graph.addEdge(edgeId, selectedNode, node);
            }

            // finish dragging
            unselectNode();
            dragStartPoint = null;
            dragCurrentPoint = null;
        }
    }

    @Override
    public void mouseEntered(MouseEvent me) {
        // DO NOTHING
    }

    @Override
    public void mouseExited(MouseEvent me) {
        // DO NOTHING
    }

    //-------------------------------------------------------------------------
    // MouseMotionListener methods
    //-------------------------------------------------------------------------
    @Override
    public void mouseDragged(MouseEvent me) {
        if (dragStartPoint != null) {
            Point location = me.getPoint();
            dragCurrentPoint = location;
            long now = System.currentTimeMillis();
            if (now - frame.lastRender() > 50) {
                graphPanel.repaint();
            }
        }
    }

    @Override
    public void mouseMoved(MouseEvent me) {
        // DO NOTHING
    }

    //-------------------------------------------------------------------------
    // KeyListener methods
    //-------------------------------------------------------------------------
    @Override
    public void keyTyped(KeyEvent ke) {
        // DO NOTHING
    }

    @Override
    public void keyPressed(KeyEvent ke) {
        // DO NOTHING
    }

    @Override
    public void keyReleased(KeyEvent ke) {
        if (selectedEdge != null && ke.getKeyCode() == KeyEvent.VK_DELETE) {
            graph.removeEdge(selectedEdge);
        }
    }

    //-------------------------------------------------------------------------
    // LayerRenderer methods
    //-------------------------------------------------------------------------
    @Override
    public void render(Graphics2D graphics, GraphicGraph graph,
            double px2Gu, int widthPx, int heightPx,
            double minXGu, double minYGu,
            double maxXGu, double maxYGu) {

        if (dragStartPoint != null && dragCurrentPoint != null) {
            Color savedColor = graphics.getColor();
            Stroke savedStroke = graphics.getStroke();
            graphics.setColor(Color.black);
            graphics.setStroke(new BasicStroke(1));
            graphics.drawLine((int) dragStartPoint.x, (int) dragStartPoint.y, (int) dragCurrentPoint.x, (int) dragCurrentPoint.y);
            graphics.setColor(savedColor);
            graphics.setStroke(savedStroke);
        }
    }

    //-------------------------------------------------------------------------
    // Private utility methods
    //-------------------------------------------------------------------------
    private boolean isNear(CoordCar c1, CoordCar c2) {
        if (c1 != null && c2 != null) {
            return Math.abs(c1.x - c2.x) < MARGIN && Math.abs(c1.y - c2.y) < MARGIN;
        }
        return false;
    }

    private Node getNode(Point p) {
        if (graphPanel instanceof DefaultView) {
            DefaultView view = (DefaultView) graphPanel;
            GraphicElement element = view.findNodeOrSpriteAt(p.x, p.y);
            if (element != null) {
                Node node = graph.getNode(element.getId());
                if (node != null) {
                    return node;
                }
            }

            Collection<GraphicElement> elements = view.allNodesOrSpritesIn(
                    p.x - MARGIN, p.y - MARGIN,
                    p.x + MARGIN, p.y + MARGIN);
            for (GraphicElement nearby : elements) {
                Node node = graph.getNode(nearby.getId());
                if (node != null) {
                    return node;
                }
            }
        }

        CoordCar coord = new CoordCar(p.x, p.y);
        for (Node node : graph.getNodeSet()) {
            CoordCar nodeCoord = frame.getCoord(node);
            if (isNear(coord, nodeCoord)) {
                return node;
            }
        }
        return null;
    }

    private Edge getEdge(Point p) {
        CoordCar coord = new CoordCar(p.x, p.y);
        for (Edge edge : graph.getEdgeSet()) {
            CoordCar coord0 = frame.getCoord(edge.getSourceNode());
            CoordCar coord1 = frame.getCoord(edge.getTargetNode());
            Segment segment = new Segment(coord0, coord1);
            if (segment.contains(coord, MARGIN)) {
                return edge;
            }
        }
        return null;
    }

    private OppEdge unselectEdge() {
        OppEdge edge = selectedEdge;
        if (selectedEdge != null) {
            selectedEdge.setTag(null);
            selectedEdge = null;
        }
        return edge;
    }

    private OppNode unselectNode() {
        OppNode node = selectedNode;
        if (selectedNode != null) {
            selectedNode.setTag(null);
            selectedNode = null;
        }
        return node;
    }
    
    private String getCommonType(OppNode node0, OppNode node1) {
        Collection<String> types = node0.getConnectivityTypes();
        for (String type : node1.getConnectivityTypes())
            if (types.contains(type))
                return type;
        return null;
    }
}
