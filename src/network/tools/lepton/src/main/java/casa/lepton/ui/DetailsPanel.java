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
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import javax.swing.AbstractListModel;
import javax.swing.JComponent;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.graphstream.graph.Element;
import org.graphstream.stream.AttributeSink;
import org.graphstream.stream.ElementSink;

/**
 * The panel that contains a list of the graph nodes and details about the
 * selected node
 */
public class DetailsPanel extends JPanel implements ElementSink, AttributeSink {

    private final OppNetGraph oppNetGraph;
    private SortedListModel<OppNode> nodesListModel;
    private SortedListModel<OppNode> nodeNeighborsModel;
    private JTextArea nodeDescription;
    private OppNode selectedNode;

    public DetailsPanel(OppNetGraph oppNetGraph) {

        setLayout(new GridLayout(2, 1, 5, 5));
        this.setPreferredSize(new Dimension(200, 200));

        this.oppNetGraph = oppNetGraph;
        this.oppNetGraph.addElementSink(this);
        this.oppNetGraph.addAttributeSink(this);

        // nodes list
        this.add(makeNodesList());

        // node details
        this.add(makeNodeDetails());
    }

    //------------------------------------------------------------------------
    // NodesList 
    //------------------------------------------------------------------------
    /**
     * Create a sorted list of nodes and add it to the current panel
     *
     * @return the model that manages the nodes in the list
     */
    private JComponent makeNodesList() {
        this.nodesListModel = new SortedListModel<>(new NodeComparator());
        JList<OppNode> nodesList = new JList<>(nodesListModel);
        nodesList.setBackground(Color.BLACK);
        nodesList.setForeground(Color.WHITE);
        nodesList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        nodesList.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent event) {
                nodesSelectionChanged(nodesList.getSelectedValue());
            }
        });
        JScrollPane scrollPane = new JScrollPane(nodesList);
        return scrollPane;
    }

    /**
     * Called when the selection changes on the nodes list
     *
     * @param selectedNode the node selected after the change
     */
    private void nodesSelectionChanged(OppNode selectedNode) {

        if (!Objects.equals(this.selectedNode, selectedNode)) {

            this.selectedNode = selectedNode;
            this.nodeNeighborsModel.clearElements();
            setSelectedNodeDescription();
            if (selectedNode != null) {
                Collection<OppNode> neighbors = selectedNode.getNeighbors(null, null);
                this.nodeNeighborsModel.addElements(neighbors);
            }
        }
    }

    private void setSelectedNodeDescription() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                if (selectedNode == null) {
                    nodeDescription.setText("");
                } else {
                    String tag = selectedNode.getTag();
                    nodeDescription.setText("node: \"" + selectedNode.getLabel() + "\""
                            + "\ntag: \"" + (tag == null ? "" : tag) + "\"");
                }
            }
        });
    }

    //------------------------------------------------------------------------
    // Node details
    //------------------------------------------------------------------------
    private JComponent makeNodeDetails() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.add(makeNodeDescription(), BorderLayout.NORTH);
        panel.add(makeNodeNeighborsList(), BorderLayout.CENTER);
        return panel;
    }

    private JComponent makeNodeDescription() {
        nodeDescription = new JTextArea();
        JScrollPane scrollPane = new JScrollPane(nodeDescription);
        return scrollPane;
    }

    private JComponent makeNodeNeighborsList() {
        this.nodeNeighborsModel = new SortedListModel<>(new NodeComparator());
        JList<OppNode> nodesList = new JList<>(nodeNeighborsModel);
        nodesList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scrollPane = new JScrollPane(nodesList);
        return scrollPane;
    }

    //------------------------------------------------------------------------
    // Inner classes
    //------------------------------------------------------------------------
    /**
     * A comparator for graph elements based on their ID
     */
    class ElementComparator<T extends Element> implements Comparator<T> {

        @Override
        public int compare(T elt1, T elt2) {
            return elt1.getId().compareTo(elt2.getId());
        }
    }

    /**
     * A comparator for nodes based on their label (or their ID, if they don't
     * have a specific label)
     */
    class NodeComparator extends ElementComparator<OppNode> {

        @Override
        public int compare(OppNode node1, OppNode node2) {
            return node1.getLabel().compareTo(node2.getLabel());
        }
    }

    //------------------------------------------------------------------------
    /**
     * Dynamic and sorted ListModel implementation. The elements are compared to
     * each others using a given comparator. The list modifications are
     * processed in the UI thread to avoid problems due to concurrency while
     * accessing the displayed elements
     *
     * @param <T> the type of the elements
     */
    class SortedListModel<T> extends AbstractListModel<T> {

        private List<T> elements;

        private final Comparator<T> comparator;

        public SortedListModel(Comparator<T> comparator) {
            this.elements = new ArrayList<>();
            this.comparator = comparator;
        }

        @Override
        public int getSize() {
            return elements.size();
        }

        @Override
        public T getElementAt(int i) {
            return elements.get(i);
        }

        public void addElements(Collection<T> elts) {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    int previousSize = elements.size();
                    elements.clear();
                    for (T elt : elts) {
                        int idx = findIdx(elt);
                        if (idx >= 0) {
                            elements.add(idx, elt);
                        }
                    }

                    if (elements.size() == previousSize) {
                        fireContentsChanged(ui, 0, previousSize - 1);
                    } else if (elements.size() > previousSize) {
                        fireContentsChanged(ui, 0, previousSize - 1);
                        fireIntervalAdded(ui, previousSize, elements.size() - 1);
                    } else {
                        fireContentsChanged(ui, 0, elements.size() - 1);
                        fireIntervalRemoved(ui, elements.size(), previousSize - 1);
                    }
                }
            });
        }

        public void addElement(T elt) {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    int idx = findIdx(elt);
                    if (idx >= 0) {
                        elements.add(idx, elt);
                        fireIntervalAdded(SortedListModel.this, idx, idx);
                    }
                }
            });
        }

        public void removeElement(T elt) {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    int idx = elements.indexOf(elt);
                    if (idx >= 0) {
                        elements.remove(idx);
                        fireIntervalRemoved(SortedListModel.this, idx, idx);
                    }
                }
            });
        }

        public void clearElements() {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    int previousSize = elements.size();
                    elements.clear();
                    fireIntervalRemoved(SortedListModel.this, 0, previousSize - 1);
                }
            });
        }

        private int findIdx(T elt) {
            if (getSize() == 0) {
                return 0;
            }
            int idx = 0;
            while (idx < getSize()) {
                int cmp = comparator.compare(getElementAt(idx), elt);
                if (cmp > 0) {
                    return idx;
                } else if (cmp == 0) {
                    return -1;
                }
                idx++;
            }
            return idx;
        }
    }

    //------------------------------------------------------------------------
    // ElementSink and AttributeSink methods
    //------------------------------------------------------------------------
    @Override
    public void nodeAdded(String sourceId, long timeId, String nodeId) {
        nodesListModel.addElement(oppNetGraph.getNode(nodeId));
    }

    @Override
    public void nodeRemoved(String sourceId, long timeId, String nodeId) {
        nodesListModel.removeElement(oppNetGraph.getNode(nodeId));
    }

    @Override
    public void edgeAdded(String sourceId, long timeId, String edgeId, String fromNodeId, String toNodeId, boolean directed) {
        if (selectedNode != null) {

            String nodeId = this.selectedNode.getId();
            OppNode neighbor = null;

            if (nodeId.equals(toNodeId)) {
                neighbor = oppNetGraph.getNode(fromNodeId);
            } else if (nodeId.equals(fromNodeId)) {
                neighbor = oppNetGraph.getNode(toNodeId);
            }

            if (neighbor != null) {
                nodeNeighborsModel.addElement(neighbor);
            }
        }
    }

    @Override
    public void edgeRemoved(String sourceId, long timeId, String edgeId) {
        if (selectedNode != null) {

            OppEdge edge = oppNetGraph.getEdge(edgeId);
            if (edge != null) {

                OppNode neighbor = null;
                OppNode node0 = edge.getNode0();
                OppNode node1 = edge.getNode1();

                if (selectedNode.equals(node0)) {
                    neighbor = node1;
                } else if (selectedNode.equals(node1)) {
                    neighbor = node0;
                }

                if (neighbor != null && node0.getEdgeSetBetween(node1).size() <= 1) {
                    nodeNeighborsModel.removeElement(neighbor);
                }
            }
        }
    }

    @Override
    public void graphCleared(String sourceId, long timeId) {
        // DO NOTHING
    }

    @Override
    public void stepBegins(String sourceId, long timeId, double step) {
        // DO NOTHING
    }

    @Override
    public void graphAttributeAdded(String sourceId, long timeId, String attribute, Object value) {
        // DO NOTHING
    }

    @Override
    public void graphAttributeChanged(String sourceId, long timeId, String attribute, Object oldValue, Object newValue) {
        // DO NOTHING
    }

    @Override
    public void graphAttributeRemoved(String sourceId, long timeId, String attribute) {
        // DO NOTHING
    }

    @Override
    public void nodeAttributeAdded(String sourceId, long timeId, String nodeId, String attribute, Object value) {
        this.nodeAttributeChanged(null, timeId, nodeId, attribute, null, null);
    }

    @Override
    public void nodeAttributeChanged(String sourceId, long timeId, String nodeId, String attribute, Object oldValue, Object newValue) {
        if (selectedNode != null && selectedNode.getId().equals(nodeId) && attribute.equals("tag")) {
            setSelectedNodeDescription();
        }
    }

    @Override
    public void nodeAttributeRemoved(String sourceId, long timeId, String nodeId, String attribute) {
        this.nodeAttributeChanged(null, timeId, nodeId, attribute, null, null);
    }

    @Override
    public void edgeAttributeAdded(String sourceId, long timeId, String edgeId, String attribute, Object value) {
        // DO NOTHING
    }

    @Override
    public void edgeAttributeChanged(String sourceId, long timeId, String edgeId, String attribute, Object oldValue, Object newValue) {
        // DO NOTHING
    }

    @Override
    public void edgeAttributeRemoved(String sourceId, long timeId, String edgeId, String attribute) {
        // DO NOTHING
    }
}
