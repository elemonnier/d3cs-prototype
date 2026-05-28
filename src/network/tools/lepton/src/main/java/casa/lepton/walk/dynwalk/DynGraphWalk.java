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
package casa.lepton.walk.dynwalk;

import casa.lepton.walk.Walker;
import casa.lepton.walk.GraphWalk;
import casa.util.geom.AreaCar;
import java.util.HashMap;
import java.util.Random;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Graph;

/**
 * Un GraphWalk dont des arcs peuvent être supprimés ou ajoutés dynamiquement
 * Les arcs sont désignés par leur identifiant dans le fichier DGS.
 * 
 */
public class DynGraphWalk extends GraphWalk {

    /**
     * identifiants des arêtes qui sont ajoutées/retirées
     */
    private HashMap<String, Edge> edges;

    // ------------------------------------------------------------
    public DynGraphWalk(AreaCar area,
            long minWait, long maxWait,
            double minSpeed, double maxSpeed,
            Graph graph,
            String pauseType,
            Random random) {
        super(area, minWait, maxWait, minSpeed, maxSpeed, graph, pauseType, random);
        edges = new HashMap<String, Edge>();
    }

    /**
     * Suppression d'un arc du graphe
     *
     * @param id identifiant de l'arc
     */
    public synchronized void removeEdge(String id) {
        if (!edges.containsKey(id)) {
            // on mémorise l'arc pour pouvoir le rajouter par la suite
            Edge edge = graph.getEdge(id);
            if (edge == null) {
                return; // pas d'arc avec cet id dans le graphe
            }
            edges.put(id, edge);
        }
        graph.removeEdge(id);
    }

    /**
     * Ajout d'un arc au graphe
     *
     * @param id de l'arc qui avait été retiré par {@link #removeEdge(String)}
     */
    public synchronized void addEdge(String id) {
        Edge edge = edges.get(id);
        if (edge == null) {
            return; // pas d'arc mémorisé avec cet id
        }
        graph.addEdge(id, edge.getSourceNode().getId(), edge.getTargetNode().getId());
    }

    @Override
    public Walker getWalker(long time, String nodeId) {
        return new DynGraphWalker(this, time, nodeId);
    }
}
