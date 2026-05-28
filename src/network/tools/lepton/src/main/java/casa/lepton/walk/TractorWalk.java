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

import casa.lepton.conf.OppNodeProperties;
import casa.util.geom.AreaCar;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.graphstream.graph.Graph;
import org.graphstream.graph.Node;

/**
 * Graphe modélisant le parcours d'un tracteur
 *
 * Le parcours d'un tracteur est composé de 3 types de noeud : - le hangar :
 * (unique) noeud étiqueté par le label "warehouse" avec la valeur true -
 * l'entrée des champs : noeud étiqueté par le label "field_entry" avec la
 * valeur true - les sillons dans le champs : ils forment un anneau connecté à
 * la route par une entrée de champ - les routes : relient le hangar aux entrées
 * de champs.
 *
 * L'ensemble des noeuds forme un {@link GraphWalk}
 *
 */
public class TractorWalk extends GraphWalk {

    /**
     * ensemble des entrées de champs
     */
    private ArrayList<Node> field_nodes;

    /**
     * le hangar
     */
    private Node warehouse_node;

    /**
     * attribut d'un noeud entrée de champ
     */
    private static final String FIELD_ATTRIBUTE = "field";
    /**
     * attribut du noeud hangar
     */
    private static final String WAREHOUSE_ATTRIBUTE = "warehouse";

    /**
     *
     * @param area
     * @param minWait
     * @param maxWait
     * @param minSpeed
     * @param maxSpeed
     * @param graph
     * @param pauseType
     * @param random
     */
    public TractorWalk(AreaCar area,
            long minWait, long maxWait,
            double minSpeed, double maxSpeed,
            Graph graph,
            String pauseType,
            Random random) {
        super(area, minWait, maxWait, minSpeed, maxSpeed, graph, pauseType, random);
        field_nodes = new ArrayList<Node>(50);
        // parcours des noeuds du graphe pour mémoriser les entrées de champs et le hangar
        Iterator<Node> node_iter = graph.getNodeIterator();
        while (node_iter.hasNext()) {
            Node node = node_iter.next();
            if (node.hasAttribute(FIELD_ATTRIBUTE)
                    && node.getAttribute(FIELD_ATTRIBUTE).equals(true)) {
                field_nodes.add(node);
            } else if (node.hasAttribute(WAREHOUSE_ATTRIBUTE)
                    && node.getAttribute(WAREHOUSE_ATTRIBUTE).equals(true)) {
                warehouse_node = node;
                System.err.println("A warehouse node has been found.");
            }
        }
        System.err.println(field_nodes.size() + " field nodes have been found.");
    }

    /* (non-Javadoc)
	 * @see casa.mobsim.walk.GraphWalk#getWalker(long, java.lang.String)
     */
    public TractorWalker getWalker(long time, String nodeId) {

        return new TractorWalker(this, nodeId, time, pauseType);
    }

    /**
     * Creates and returns an instance of {@link TractorWalk}, using system
     * properties (if defined) in order to initialize this object, and using
     * default values otherwise.
     *
     * @return a {@link TractorWalk} object, initialized using either system
     * properties or default values
     */
    public static TractorWalk getDefault(OppNodeProperties props) {

        double min_speed = props.getMinSpeed();
        double max_speed = props.getMaxSpeed();

        long min_wait = props.getMinWait();
        long max_wait = props.getMaxWait();

        String pause_type = props.getPauseType();

        long seed = props.getSeed();
        Random random = new Random(seed);

        // read graph
        File graphFile = props.getGraph();
        if (graphFile == null) {
            System.err.println("Missing name of graph file for GraphWalk");
            System.exit(1);
        }
        Graph graph = readGraph(graphFile.getAbsolutePath());

        // initialize simulation area
        double x = 0, y = 0;
        if (graph.hasAttribute("x")) {
            x = graph.getAttribute("x");
        }
        if (graph.hasAttribute("y")) {
            y = graph.getAttribute("y");
        }
        double width = graph.getAttribute("width");
        double height = graph.getAttribute("height");
        AreaCar area = new AreaCar(x, y, width, height);
        System.err.println("area=" + area);

        walk_ = new TractorWalk(area,
                min_wait, max_wait,
                min_speed, max_speed,
                graph,
                pause_type,
                random);

        return (TractorWalk) walk_;

    }

    /**
     * Choisit un noeud au hasard qui soit une entrée de champ différente d'une
     * entrée donnée
     *
     * @param current_field un noeud entrée de champ ou null
     * @return un autre noeud entrée de champ ou null s'il n'en existe pas de
     * différent de celui donné
     */
    public Node getRandomField(Node current_field) {
        Node next_field = null;
        if ((field_nodes.size() == 1) && (current_field != null)) {
            return null;
        }
        do {
            int idx = walk_.random.nextInt(field_nodes.size());
            next_field = field_nodes.get(idx);
        } while (next_field == current_field);
        return next_field;
    }

    /**
     * Accesseur du noeud hangar
     *
     * @return le noeud hangar
     */
    public Node getWarehouse() {
        return warehouse_node;
    }

    /**
     * Noeud du rang suivant dans le parcours du champ
     *
     * @param previous_row noeud du rang précédent
     * @param next_row noeud du rang suivant
     * @return le noeud voisin qui représente le rang suivant ou null s'il
     * n'existe pas
     */
    private Node getNextRow(Node previous_row, Node current_row) {
        // chaque rang a deux voisins : le rang précédent d'où l'on vient 
        // et le rang suivant que l'on cherche

        Node next_row;
        try {
            next_row = current_row.getLeavingEdge(0).getOpposite(current_row);
            if (next_row == previous_row) { // on est pas tombé sur le bon, on prend le suivant !
                next_row = current_row.getLeavingEdge(1).getOpposite(current_row);
            }
        } catch (IndexOutOfBoundsException e) {
            next_row = null;
        }
        return next_row;
    }

    /**
     * Construction d'un chemin permettant de parcourir la totalité d'un champ
     * et de revenir au point de départ en suivant des rangs
     *
     * @param tractor_id identifiant du tracteur
     * @param road_node noeud sur la route, précédant l'entrée du champ
     * @param field_node noeud de l'entrée du champ
     * @return le chemin parcourant tous les rangs du champ et se terminant par
     * l'entrée du champ ou null si aucun chemin n'a été trouvé
     */
    public List<Node> getRowPath(String tractor_id, Node road_node, Node field_node) {
        //String road_id= road_node.getId(); // DEBUG
        //String field_id= field_node.getId();// DEBUG
        List<Node> path = new LinkedList<Node>();
        path.add(field_node);
        int node_degree = field_node.getDegree();
        if (node_degree != 3) {
            return null; // pas normal, ce n'est pas une entrée de champ ?
        }		// il faut identifier le rang de départ (un des trois voisins qui n'est pas la route)
        Node previous_row = road_node;
        Node current_row = field_node;
        // il construire le chemin jusqu'au noeud de départ (l'entrée du champ)
        //int cpt= 0; // DEBUG
        do {
            Node next_row = getNextRow(previous_row, current_row);
            if (next_row == null) {
                return null;
            }
            path.add(next_row);
            previous_row = current_row;
            current_row = next_row;
            //cpt += 1;
            //if (cpt % 1000 == 0){ // DEBUG : PB !
            //	System.err.println("tractor_id= "+tractor_id+"\nroad_id= "+road_id+"\nfield_id= "+field_id);
            //	return null;
            //}
        } while (current_row != field_node);
        path.add(current_row);
        return path;
    }
}
