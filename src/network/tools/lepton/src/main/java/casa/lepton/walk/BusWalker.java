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

import casa.lepton.walk.BusJourney.BusNode;
import casa.util.geom.CoordCar;
import java.util.Iterator;

/**
 * A {@link Walker} for a bus that follows a given journey with fixed times at
 * some bus stops.
 *
 */
public class BusWalker implements Walker {

    private static final long DELAY = 180000; // min delay to set the node offline

    private final BusWalk walk;               // the walk
    private final Iterator<BusNode> it;       // bus nodes

    private BusNode startNode;                // the start node of the next step
    private long startTime;                   // the start time of the next step

    private Step step;                        // the current step

    private boolean mobile;                   // true if the current step has separate start and end nodes

    /**
     * Constructor
     *
     * @param walk the walk
     * @param journey the bus journey
     * @param pauseSeed the seed to generate random pause durations
     */
    public BusWalker(BusWalk walk, BusJourney journey, long pauseSeed) {
        this.walk = walk;
        this.it = journey.iterator(pauseSeed);
        if (it.hasNext()) {
            startNode = it.next();
            startTime = journey.getStartTime() + startNode.getPauseDuration();
            if (it.hasNext()) {
                step = makeStep(it.next());
            }
        }
    }

    @Override
    public BusWalk getWalk() {
        return walk;
    }

    @Override
    public CoordCar getPosition(long time) {
        while (step != null && time >= step.timeOfCompletion()) {
            step = nextStep();
        }
        if (step != null) {

            if (step.timeOfDeparture() - time > DELAY) {
                // bus not started
                return null;
            } else if (!mobile && (time - step.timeOfDeparture() > DELAY || step.timeOfCompletion() - time > DELAY)) {
                // long pause at the terminus
                return null;
            }

            return step.getPosition(time);
        }
        return null;
    }

    @Override
    public Step getStep() {
        return step;
    }

    @Override
    public Step nextStep() {
        if (it.hasNext()) {
            step = makeStep(it.next());
        } else {
            step = null;
        }
        return step;
    }

    /**
     * Make a step given a node and the startNode/startTime
     *
     * @param node The end node of the step
     * @return the step
     */
    private Step makeStep(BusNode node) {
        CoordCar dep = new CoordCar(startNode.getX(), startNode.getY());
        CoordCar arr = new CoordCar(node.getX(), node.getY());
        long timeOfDep = startTime;
        long endTime = startNode.getNextNodeArrivalTime(startTime);
        long flightDuration = endTime - startTime;
        long pauseDuration = node.getPauseDuration();
        startNode = node;
        startTime = endTime;
        mobile = dep.x != arr.x || dep.y != arr.y;
        return new Step(dep, arr, timeOfDep, flightDuration, pauseDuration);
    }
}
