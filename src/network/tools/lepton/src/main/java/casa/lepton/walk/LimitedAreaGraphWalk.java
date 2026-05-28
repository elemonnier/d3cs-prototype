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
import casa.lepton.conf.OppNodeProperties;
import casa.util.geom.AreaCar;
import java.io.File;
import java.util.Random;
import org.graphstream.graph.Graph;

/**
 * A {@link Walk} that defines a mobility model where nodes move along an
 * underlying graph ({@link GraphWalk}), but inside a given area inside this
 * graph potentially smaller than the whole graph area.
 *
 */
public class LimitedAreaGraphWalk extends GraphWalk {

    public LimitedAreaGraphWalk(AreaCar area,
            long minWait, long maxWait,
            double minSpeed, double maxSpeed,
            Graph graph,
            String pauseType,
            Random random) {

        super(area, minWait, maxWait,
                minSpeed, maxSpeed,
                graph,
                pauseType,
                random);
    }

    public static GraphWalk getDefault(OppNodeProperties props) {

        if (walk_ != null) {
            return walk_;
        }

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
        DGSAttributes graphAttributes = new DGSAttributes(graph);

        // initialize simulation area
        double x = graphAttributes.getDouble("x", 0);
        double y = graphAttributes.getDouble("y", 0);
        double width = graphAttributes.getDouble("width", 0);
        double height = graphAttributes.getDouble("height", 0);
        AreaCar area = new AreaCar(x, y, width, height);
        System.err.println("area=" + area);

        walk_ = new LimitedAreaGraphWalk(area,
                min_wait, max_wait,
                min_speed, max_speed,
                graph,
                pause_type,
                random);

        return walk_;
    }

    @Override
    public Walker getWalker(long time, String nodeId) {

        return new LimitedAreaGraphWalker(this, time, pauseType);
    }

}
