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

/**
 * A {@link Walker} that implements the random way point mobility model.
 *
 */
public class RandomWaypointWalker implements Walker {

    private RandomWaypoint walk_;
    private Step step_;

    // ------------------------------------------------------------
    public RandomWaypointWalker(RandomWaypoint walk, long time) {

        walk_ = walk;
        double x = walk_.random.nextDouble() * walk_.area.width + walk_.area.x;
        double y = walk_.random.nextDouble() * walk_.area.height + walk_.area.y;
        CoordCar pos = new CoordCar(x, y);
        step_ = new Step(pos, pos, time, 0.0, 0);
        nextStep();
    }

    // ------------------------------------------------------------
    public Walk getWalk() {

        return walk_;
    }

    // ------------------------------------------------------------
    public Step getStep() {

        return step_;
    }

    // ------------------------------------------------------------
    private double getUniformValue(double min, double max) {

        return min + (walk_.random.nextDouble() * (max - min));
    }

    // ------------------------------------------------------------
    public CoordCar getPosition(long time) {

        if (time >= step_.timeOfCompletion()) {
            // Time to compute the next step
            nextStep(time);
            return step_.departure();
        }

        return step_.getPosition(time);
    }

    // ------------------------------------------------------------
    public Step nextStep(long time) {

        // Choose departure and arrival positions
        CoordCar departure = step_.getPosition(time);
        double x = walk_.random.nextDouble() * walk_.area.width + walk_.area.x;
        double y = walk_.random.nextDouble() * walk_.area.height + walk_.area.y;
        CoordCar arrival = new CoordCar(x, y);

        // Choose speed - Uniform distribution
        double speed = getUniformValue(walk_.minSpeed,
                walk_.maxSpeed);

        // Choose pause duration - Uniform distribution
        long pauseDuration = (long) getUniformValue(walk_.minWait,
                walk_.maxWait);

        step_ = new Step(departure, arrival,
                time, speed,
                pauseDuration);

        return step_;
    }

    // ------------------------------------------------------------
    public Step nextStep() {

        long time = step_.timeOfCompletion();
        return nextStep(time);
    }

}
