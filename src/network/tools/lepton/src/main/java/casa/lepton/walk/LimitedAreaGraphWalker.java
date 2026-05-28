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

import casa.dgs.DGSAttributes;
import java.util.Random;
import org.graphstream.graph.Node;

/**
 * A {@link GraphWalker} limited to some given area inside the underlying graph.
 *
 */
public class LimitedAreaGraphWalker extends GraphWalker {

    private final Random randomizer = new Random();

    public LimitedAreaGraphWalker(GraphWalk walk, long time,
            String pauseType) {
        super(walk, time, pauseType);
    }

    @Override
    protected Node selectNode(String pauseType) {
        int nbNodes = walk_.graph.getNodeCount();
        Node node = departureNode_;
        boolean found = false;
        if (node == null || randomizer.nextInt(100) > 80) {
            do {
                int idx = walk_.random.nextInt(nbNodes);
                node = walk_.graph.getNode(idx);
                if (pauseType == null) {
                    found = true;
                } else {
                    DGSAttributes nodeAttributes = new DGSAttributes(node);
                    String area = nodeAttributes.get("area");
                    found = (area != null) && (area.startsWith(pauseType));
                }
            } while (!found);
        }
        return node;
    }
}
