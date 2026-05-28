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
 * The mobility of a mobile element that moves according to the so-called Levy
 * walk patterns.
 *
 */
public class LevyWalker implements Walker {

    private LevyWalk walk_;
    private Step step_;

    // ------------------------------------------------------------
    public LevyWalker(LevyWalk walk, long time) {

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
    private double getLevyValue(double min, double max,
            double coef) {

        double interval = max - min;
        double result;
        double maxV = Math.pow(0.01d, -1.0d / (1.0d + coef));
        do {
            double rand = walk_.random.nextDouble();
            result = interval * (Math.pow(rand, -1.0d
                    / (1.0d + coef))
                    / maxV) + min;
        } while ((result > max) || (result < min));

        return result;
    }

    // ------------------------------------------------------------
    private double getUniformValue(double min, double max) {

        return min + (walk_.random.nextDouble() * (max - min));
    }

    // ------------------------------------------------------------
    private double getFlightDuration(double distance, double k, double rho) {

        return k * Math.pow(distance, 1 - rho);
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
    public Step nextStep_Rhee(long time) {

        CoordCar departure = step_.getPosition(time);

        // Choose distance - p(l) ∼ 1/l^(1+α), 0 < α < 2
        double distance = getLevyValue(walk_.minDist,
                walk_.maxDist,
                walk_.alpha);

        // Choose direction - Uniform distribution
        double direction = getUniformValue(0.0, 2 * Math.PI);

        // Choose fligt duration
        double flightDuration = getFlightDuration(distance, walk_.k, walk_.rho);

        // -----------------------------------------------------------
        // FG: pour simulation conformément au papier de Rhee et
        // al. (On the Levy-walk nature of human mobility). N'a de
        // sens que si maxDist >> 500 m.
        //
        // double k, rho;
        // if (distance < 500) {
        //     k = 30.55; rho = 1.89;
        // }
        // else {
        //     k = 0.76; rho = 0.28;
        // }
        // flightDuration = getFlightDuration(distance, k, rho);
        // -----------------------------------------------------------
        // Compute speed based on distance and flight duration
        double speed = distance / flightDuration;

        // Choose pause duration - ψ(∆tp) ∼ 1/∆tp^(1+β)
        long pauseDuration = (long) getLevyValue(walk_.minWait,
                walk_.maxWait,
                walk_.beta);

        double dX = distance * Math.cos(direction);
        double dY = distance * Math.sin(direction);

        double x = departure.x + dX;
        if ((x < walk_.area.x) || (x > walk_.area.width + walk_.area.x)) {
            x = departure.x - dX;
        }

        double y = departure.y + dY;
        if ((y < walk_.area.y) || (y > walk_.area.height + walk_.area.y)) {
            y = departure.y - dY;
        }

        CoordCar arrival = new CoordCar(x, y);

        // Choose pause duration - Uniform distribution
        // long pauseDuration = (long)getUniformValue(walk_.minWait, 
        // 					   walk_.maxWait);
        step_ = new Step(departure, arrival,
                time, speed,
                pauseDuration);

        return step_;
    }

    // ------------------------------------------------------------
    public Step nextStep_CASA(long time) {

        CoordCar departure = step_.getPosition(time);

        // Choose distance - p(l) ∼ 1/l^(1+α), 0 < α < 2
        double distance = getLevyValue(walk_.minDist,
                walk_.maxDist,
                walk_.alpha);

        // Choose direction - Uniform distribution
        double direction = getUniformValue(0.0, 2 * Math.PI);

        // Choose speed - Uniform distribution
        double speed = getUniformValue(walk_.minSpeed,
                walk_.maxSpeed);

        double dX = distance * Math.cos(direction);
        double dY = distance * Math.sin(direction);

        double x = departure.x + dX;
        if ((x < walk_.area.x) || (x > walk_.area.width + walk_.area.x)) {
            x = departure.x - dX;
        }

        double y = departure.y + dY;
        if ((y < walk_.area.y) || (y > walk_.area.height + walk_.area.y)) {
            y = departure.y - dY;
        }

        CoordCar arrival = new CoordCar(x, y);

        // Choose pause duration - ψ(∆tp) ∼ 1/∆tp^(1+β)
        // long pauseDuration = (long)getLevyValue(walk_.minWait, 
        // 					walk_.maxWait, 
        // 					walk_.beta);
        // Choose pause duration - Uniform distribution
        long pauseDuration = (long) getUniformValue(walk_.minWait,
                walk_.maxWait);

        step_ = new Step(departure, arrival,
                time, speed,
                pauseDuration);

        return step_;
    }

    // ------------------------------------------------------------
    public Step nextStep(long time) {

        Step result = nextStep_Rhee(time);
        // Step result = nextStep_CASA(time);

//        System.err.println(result.distance()
//                + "\t" + result.pauseDuration()
//                + "\t" + result.speed());
        return result;
    }

    // ------------------------------------------------------------
    public Step nextStep() {

        long time = step_.timeOfCompletion();
        return nextStep(time);
    }

}
