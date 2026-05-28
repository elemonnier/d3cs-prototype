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

/**
 * This interface is implemented by classes that listen to network changes:
 * connections and disconnections between nodes.
 *
 */
public interface OppEdgeListener {

    /**
     * An edge has been added between two nodes.
     *
     * @param nodeId the other node id
     * @param edgeStatus the status of the edge
     */
    public void edgeAdded(String nodeId, String edgeStatus);

    /**
     * An edge has been removed between two nodes.
     *
     * @param nodeId the other node id
     * @param edgeStatus the status of the edge
     */
    public void edgeRemoved(String nodeId, String edgeStatus);

    /**
     * The status of an edge between two nodes changed.
     *
     * @param nodeId the other node id
     * @param edgeStatus the status of the edge
     */
    public void edgeChanged(String nodeId, String edgeStatus);
}
