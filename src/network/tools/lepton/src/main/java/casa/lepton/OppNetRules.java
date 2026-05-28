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

import org.graphstream.graph.Node;

/**
 * Interface defining some methods that may be used by a {@link OppNetGraph} to
 * follow some rules while changing the edge/node status.
 *
 */
public interface OppNetRules {

    public static final String ADDED = "ADDED";
    public static final String REMOVED = "REMOVED";
    public static final String CHANGED = "CHANGED";

    /**
     * Check whether the edge is allowed to change its status.
     *
     * @param edge the edge with its previous status
     * @param newStatus the status that edge will have if allowed
     * @return true if the new status is allowed for the edge
     */
    public boolean statusAllowed(OppEdge edge, String newStatus);

    /**
     * Compute the new node status according to the edge status.
     *
     * @param edge an edge between the nodes
     * @param command the command that just occured for the edge
     * (ADDED/REMOVED/CHANGED)
     * @return {sourceNodeStatus, targetNodeStatus} or null if the status are
     * not changed
     */
    public String[] nodeStatus(OppEdge edge, String command);
}
