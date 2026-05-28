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
 * An instance of type {@link LevyWalk} defines a mobility model for a random
 * walk that complies with the so-called Levy walk patterns.
 *
 */
public class LevyWalk
        implements Walk {

    public AreaCar area;

    public double alpha;
    public double beta;
    public double k;
    public double rho;

    public double minDist;
    public double maxDist;
    public long minWait;
    public long maxWait;
    public double minSpeed;
    public double maxSpeed;

    public Random random;

    // ------------------------------------------------------------
    /**
     * Creates and returns an instance of {@link LevyWalk}, using system
     * properties (if defined) in order to initialize this object, and using
     * default values otherwise.
     *
     * @return a {@link LevyWalk} object, initialized using either system
     * properties or default values
     */
    public static LevyWalk getDefault(OppNodeProperties props) {

        double alpha = props.getAlpha();
        double beta = props.getBeta();
        double k = props.getK();
        double rho = props.getRho();

        double min_speed = props.getMinSpeed();
        double max_speed = props.getMaxSpeed();

        long min_wait = props.getMinWait();
        long max_wait = props.getMaxWait();

        double min_dist = props.getMinDist();
        double max_dist = props.getMaxDist();

        long seed = props.getSeed();
        Random random = new Random(seed);

        AreaCar area = props.getWalkArea();
        LevyWalk walk = new LevyWalk(area,
                alpha, beta, k, rho,
                min_wait, max_wait,
                min_dist, max_dist,
                min_speed, max_speed,
                random);

        return walk;
    }

    // ------------------------------------------------------------
    public LevyWalk(AreaCar area,
            double alpha, double beta, double k, double rho,
            long minWait, long maxWait,
            double minDist, double maxDist,
            double minSpeed, double maxSpeed,
            Random random) {

        this.area = area;
        this.alpha = alpha;
        this.beta = beta;
        this.k = k;
        this.rho = rho;
        this.minDist = minDist;
        this.maxDist = maxDist;
        this.minWait = minWait;
        this.maxWait = maxWait;
        this.minSpeed = minSpeed;
        this.maxSpeed = maxSpeed;
        this.random = random;
    }

    // ------------------------------------------------------------
    public Walker getWalker(long time, String nodeId) {

        return new LevyWalker(this, time);
    }

    // ------------------------------------------------------------
    public AreaCar getArea() {

        return area;
    }

    // ------------------------------------------------------------
    /**
     * Returns a {@link String} representation of this {@link LevyWalk} object.
     *
     * @return a {@link String} representation of this object
     */
    public String toString() {

        return "Levy Walk -- alpha=" + alpha
                + ", beta=" + beta
                + ", k=" + k
                + ", rho=" + rho
                + ", wait=[" + minWait + "," + maxWait
                + "], dist=[" + minDist + "," + maxDist
                + "], speed=[" + minSpeed + "," + maxSpeed + "]";
    }

}
