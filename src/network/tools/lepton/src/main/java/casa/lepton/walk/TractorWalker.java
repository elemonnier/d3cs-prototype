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

import casa.util.geom.CoordCar;
import org.graphstream.graph.Node;
import org.graphstream.graph.Path;

/**
 * Modélisation du comportement d'un tracteur qui : - quitte le hangar (après
 * une pause aléatoire) - choisi un champ (l'entrée d'un champ) - chemine
 * jusqu'à l'entrée de ce champ en suivant des routes - sillonne le champ - sort
 * du champ - retourne au hangar ou choisit un nouveau champ - recommence après
 * une pause aléatoire dans le hangar.
 *
 */
public class TractorWalker extends GraphWalker {

    /**
     * probabilité d'attendre au démarrage dans le hangar
     */
    private static final double START_WAITING_PROBABILITY = 0.75;

    /**
     * probabilité de se diriger vers un autre champ plutot que vers le hangar
     */
    private static final double ANOTHER_FIELD_PROBABILITY = 0.25;

    /**
     * prochain champ à atteindre ou le hangar
     */
    private Node target_node;

    /**
     * le label associé au noeud dans la fenêtre graphique de graphstream
     */
    private String tractor_id;

    /**
     * le hangar
     */
    private Node warehouse_node;

    /**
     * Affichage d'un message de trace sur stderr précédé du nom du noeud
     *
     * @param msg le message
     */
    private void log(String msg) {

        System.err.println("[tractor " + tractor_id + "] " + msg);
    }

    // ------------------------------------------------------------
    public TractorWalker(TractorWalk walk, String nodeId, long time, String pauseType) {

        walk_ = walk;
        if (pauseType != null) {
            this.pauseType = pauseType + ":";
        }
        tractor_id = nodeId;
        //log("is created");
        warehouse_node = walk.getWarehouse(); // recherche du hangar
        if (warehouse_node == null) {
            log("** Error: unable to find the warehouse, exiting");
            return;
        }
        // Some of the walkers should move immediately upon their
        // creation, others should wait for a while before starting
        // moving
        boolean paused = (walk_.random.nextDouble() < START_WAITING_PROBABILITY);
        //log("paused= "+paused);
        //log("maxWait= "+walk_.maxWait);
        long pauseDuration = paused ? (long) getUniformValue(0, walk_.maxWait) : 0;
        //log("pause duration= "+pauseDuration);
        speed_ = 0.0;
        CoordCar pos = getCoordAround(warehouse_node); // position de départ (le hangar)
        departureNode_ = warehouse_node;
        arrivalNode_ = warehouse_node;
        //log("starting from node "+departureNode_.getId());
        step_ = new Step(pos, pos, time, speed_, pauseDuration);
    }

    /**
     * Choisit au hasard : - un champ si le tracteur est au hangar - un autre
     * champ ou le hangar si le tracteur est déjà dans un champ Méthode appelée
     * quand le tracteur est au hangar ou bien sort d'un champ.
     *
     * @param le noeud courant (le hangar ou une entrée/sortie de champ)
     * @return le noeud choisit comme cible du prochain déplacement
     */
    private Node selectTarget(Node current_node) {

        Node target_node = null;
        if (current_node == warehouse_node) { // est au hangar
            target_node = ((TractorWalk) walk_).getRandomField(null);
        } else // sort d'un champ
        {
            if (walk_.random.nextDouble() < ANOTHER_FIELD_PROBABILITY) { // repart dans un champ
                target_node = ((TractorWalk) walk_).getRandomField(current_node);
                if (target_node == null) { // pas d'autre champ existant
                    target_node = warehouse_node;
                }
            } else { // retour au hangar
                target_node = warehouse_node;
            }
        }
        //log("has selected target node "+target_node.getId());
        return target_node;
    }

    public Step nextStep(long time) {

        if ((path_ == null) || path_.isEmpty()) {
            do {
                computeNextPath(time);
            } while (path_ == null);
            // First node in path should be departureNode_
            if (!path_.isEmpty()) {
                path_.remove(0);
            }
        }
        departureNode_ = arrivalNode_;
        arrivalNode_ = path_.remove(0);
        boolean endOfPath = path_.isEmpty();
        step_ = getStep(time, departureNode_, arrivalNode_, endOfPath);
        return step_;
    }

    /* (non-Javadoc)
	 * @see casa.mobsim.walk.GraphWalker#computeNextPath(long)
     */
    public void computeNextPath(long time) {

        // arrivalNode_ est le noeud courant
        // departureNode_ est le noeud précédent le noeud courant
        //log("compute next path from node "+arrivalNode_.getId());
        if (target_node == null) { // sort du hangar ou d'un champ
            //log("is leaving the warehouse");
            target_node = selectTarget(arrivalNode_); // choisit un champ
            //log("my next target is "+target_node.getId());
            Path shortest_path = walk_.getShortestPath(arrivalNode_.getId(), target_node.getId());
            if (shortest_path == null) {
                log("** Error: no path found from " + arrivalNode_.getId() + " to " + target_node.getId());
                path_ = null;
                target_node = null;
                return;
            } else {
                path_ = shortest_path.getNodePath();
                //log("has computed a new path from "+arrivalNode_.getId()+" to "+target_node.getId());
            }
        } else if (target_node == warehouse_node) { // arrive à l'entrée du hangar
            target_node = null;
            path_ = null; // provoquera un nouveau départ du hangar
            //log("is comming back to the warehouse");
        } else { // arrive à l'entrée d'un champ
            // construction du chemin qui permet de parcourir l'ensemble du champ et de revenir à l'entrée
            //log("looking for a path across the field from "+arrivalNode_.getId());
            path_ = ((TractorWalk) walk_).getRowPath(tractor_id, departureNode_, arrivalNode_);
            if (path_ == null) {
                log("** Error: no path found to pass across the field from " + departureNode_.getId());
                target_node = null;
                return;
            }
            //target_node= departureNode_;
            //log("has compute a new path to pass accross the field from "+arrivalNode_.getId());
            target_node = null;
        }
        speed_ = getUniformValue(walk_.minSpeed, walk_.maxSpeed);
    }
}
