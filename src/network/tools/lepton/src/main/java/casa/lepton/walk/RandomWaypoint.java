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

import casa.lepton.conf.OppNodeProperties;
import casa.util.geom.AreaCar;

import java.util.Random;

/**
 * An instance of type {@link RandomWaypoint} defines a mobility model for a
 * random walk that complies with the so-called Random Waypoint patterns.
 */
public class RandomWaypoint
        implements Walk {

    public AreaCar area;

    public long minWait;
    public long maxWait;
    public double minSpeed;
    public double maxSpeed;

    public Random random;

    // ------------------------------------------------------------
    /**
     * Creates and returns an instance of {@link RandomWaypoint}, using system
     * properties (if defined) in order to initialize this object, and using
     * default values otherwise.
     *
     * @return a {@link RandomWaypoint} object, initialized using either system
     * properties or default values
     */
    public static RandomWaypoint getDefault(OppNodeProperties props) {

        double min_speed = props.getMinSpeed();
        double max_speed = props.getMaxSpeed();

        long min_wait = props.getMinWait();
        long max_wait = props.getMaxWait();

        long seed = props.getSeed();
        Random random = new Random(seed);

        AreaCar area = props.getWalkArea();
        RandomWaypoint walk = new RandomWaypoint(area,
                min_wait, max_wait,
                min_speed, max_speed,
                random);
        return walk;
    }

    // ------------------------------------------------------------
    public RandomWaypoint(AreaCar area,
            long minWait, long maxWait,
            double minSpeed, double maxSpeed,
            Random random) {

        this.area = area;
        this.minWait = minWait;
        this.maxWait = maxWait;
        this.minSpeed = minSpeed;
        this.maxSpeed = maxSpeed;
        this.random = random;
    }

    // ------------------------------------------------------------
    public Walker getWalker(long time, String nodeId) {

        return new RandomWaypointWalker(this, time);
    }

    // ------------------------------------------------------------
    public AreaCar getArea() {

        return area;
    }

    // ------------------------------------------------------------
    /**
     * Returns a {@link String} representation of this {@link RandomWaypoint}
     * object.
     *
     * @return a {@link String} representation of this object
     */
    @Override
    public String toString() {

        return "Random Waypoint -- area=" + area.x + "," + area.y
                + " " + area.width + " x " + area.height
                + ", wait=[" + minWait + "," + maxWait
                + "], speed=[" + minSpeed + "," + maxSpeed + "]";
    }

}
