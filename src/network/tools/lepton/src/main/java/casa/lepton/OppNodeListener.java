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

import casa.util.geom.CoordCar;

/**
 * This interface is implemented by classes that listen to network changes:
 * nodes apprearing/disappearing or moving.
 *
 */
public interface OppNodeListener {

    /**
     * A node has been added in the graph.
     *
     * @param nodeId the node id
     */
    public void nodeAdded(String nodeId);

    /**
     * A node has been removed from the graph.
     *
     * @param nodeId the node id
     */
    public void nodeRemoved(String nodeId);

    /**
     * The node location has changed
     *
     * @param nodeId the node id
     * @param coord the new node location
     */
    public void nodeMoved(String nodeId, CoordCar coord);

}
