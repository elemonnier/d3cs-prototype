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

import casa.lepton.conf.OppNetProperties;
import casa.lepton.walk.Walk;
import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;

/**
 * A {@link OppNetGraph} which nodes move using a
 * {@link casa.lepton.walk.Walker}.
 *
 */
public class OppNetGraphWalk extends OppNetGraph {

    //-------------------------------------------------------------------------
    /**
     * Constructor.
     *
     * @param networkId a network id.
     * @param props
     * @throws java.io.IOException
     */
    public OppNetGraphWalk(String networkId, OppNetProperties props) throws IOException {

        super(networkId, props);

        // write dgs ref_time
        if (dgsWriter != null && refTime != 0) {
            addAttribute("ref_time", refTime);
            println(dgsWriter, "cg " + graphAttributes.toString("ref_time"));
        }

        // write area dimensions (if any)
        Walk walk = props.getOppNodeProperties().getWalk();
        if (walk != null) {
            setArea(walk.getArea());
        }
    }

    //-------------------------------------------------------------------------
    /**
     * Run a simulation step: move nodes using their walker and update edges
     * accordingly.
     *
     * @return true if this step is not the last one
     */
    @Override
    public boolean step() {

        if ((duration > 0) && (currentStep > duration)) // the simulation duration is reached: stop simulation
        {
            return false;
        }

//        System.out.println("Step " + currentStep);
        super.stepBegins(currentStep);

        moveNodes();

        waitUntil(currentStep + period);

        return true;
    }

    //-------------------------------------------------------------------------
    private synchronized void moveNodes() {
        Collection<OppNode> nodes = getNodeSet();
        Collection<OppNode> movedNodes = new HashSet<>();
        // move nodes
        for (OppNode node : nodes) {
            boolean moved = node.walk(currentStep);
            if (moved) {
                notifyNodeListeners(node, NODE_MOVED);
                logDGS("cn " + node.toDGS());
                movedNodes.add(node);
            }
        }

        updateEdges(movedNodes);
    }
}
