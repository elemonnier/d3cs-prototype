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
 * Interface for class that fire events catched by {@link OppEdgeListener} or
 * {@link OppNodeListener} instances.
 * 
 */
public interface OppNetEventsSource {

    /**
     * Add a new listener interested in edge events for the given node.
     *
     * @param nodeId a node id.
     * @param connectivityType a connectivity type.
     * @param listener the new listener.
     */
    public void addEdgeListener(String nodeId,
            String connectivityType, OppEdgeListener listener);

    /**
     * Remove a listener interested in edge events for the given node.
     *
     * @param nodeId a node id.
     * @param connectivityType a connectivity type.
     */
    public void removeEdgeListener(String nodeId, String connectivityType);

    /**
     * Add a new listener interested in node events for a specific node.
     *
     * @param nodeId a node id.
     * @param listener the new listener.
     */
    public void addNodeListener(String nodeId, OppNodeListener listener);

    /**
     * Remove a listener interested in node events.
     *
     * @param nodeId a node id.
     */
    public void removeNodeListener(String nodeId);
}
