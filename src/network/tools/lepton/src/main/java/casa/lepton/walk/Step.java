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
 * Defines a step in a {@link Walk}. A step combines a flight (i.e., a move
 * between two points) and a pause. The flight is basically characterized by a
 * point and time of departure, and a point and time of arrival. The distance
 * between both points can be determined, as well as the duration of the flight.
 * The pause occurs at the point of arrival, and it is simply characterized by
 * its duration.
 *
 */
public class Step {

    private CoordCar departure_;
    private long timeOfDeparture_;
    private CoordCar arrival_;
    private long timeOfArrival_;
    private double distance_;      // in m
    private double speed_;         // in m/s 
    private long flightDuration_;  // in ms
    private long pauseDuration_;   // in ms

    // ------------------------------------------------------------
    public Step(CoordCar dep, CoordCar arr,
            long timeOfDep, double speed,
            long pauseDuration) {

        departure_ = dep;
        timeOfDeparture_ = timeOfDep;
        arrival_ = arr;
        distance_ = dep.distanceTo(arr);
        speed_ = speed;
        if (speed == 0.0) {
            flightDuration_ = 0;
        } else {
            flightDuration_ = (long) (1000 * distance_ / speed);
        }
        pauseDuration_ = pauseDuration;
        timeOfArrival_ = timeOfDep + flightDuration_;
    }

    // ------------------------------------------------------------
    public Step(CoordCar dep, CoordCar arr,
            long timeOfDep, long flightDuration,
            long pauseDuration) {

        departure_ = dep;
        timeOfDeparture_ = timeOfDep;
        arrival_ = arr;
        distance_ = dep.distanceTo(arr);
        flightDuration_ = flightDuration;
        pauseDuration_ = pauseDuration;
        timeOfArrival_ = timeOfDep + flightDuration;
        if (flightDuration == 0) {
            speed_ = 0.0;
        } else {
            speed_ = 1000 * distance_ / flightDuration;
        }
    }

    // ------------------------------------------------------------
    /**
     * Returns the point of departure of this {@link Step}
     *
     * @return the point of departure of this {@link Step}
     */
    public CoordCar departure() {

        return departure_;
    }

    // ------------------------------------------------------------
    /**
     * Returns the time of departure of this {@link Step} (EPOCH time in ms)
     *
     * @return the time of departure of this {@link Step}
     */
    public long timeOfDeparture() {

        return timeOfDeparture_;
    }

    // ------------------------------------------------------------
    /**
     * Returns the point of arrival of this {@link Step}
     *
     * @return the point of arrival of this {@link Step}
     */
    public CoordCar arrival() {

        return arrival_;
    }

    // ------------------------------------------------------------
    /**
     * Returns the time of arrival of this {@link Step} (EPOCH time in ms)
     *
     * @return the time of arrival of this {@link Step}
     */
    public long timeOfArrival() {

        return timeOfArrival_;
    }

    // ------------------------------------------------------------
    /**
     * Returns the time of completion of this {@link Step} (time of arrival +
     * pause duration) (EPOCH time in ms)
     *
     * @return the time of completion of this {@link Step}
     */
    public long timeOfCompletion() {

        return timeOfArrival_ + pauseDuration_;
    }

    // ---------------------------------------------
    /**
     * Returns the distance covered by this {@link Step} (distance between point
     * of departure and point of arrival, in meters)
     *
     * @return the distance covered by this {@link Step}
     */
    public double distance() {

        return distance_;
    }

    // ------------------------------------------------------------
    /**
     * Returns the duration of the flight in this {@link Step} (time of arrival
     * - time of departure, in ms)
     *
     * @return the duration of the flight in this {@link Step}
     */
    public long flightDuration() {

        return flightDuration_;
    }

    // ------------------------------------------------------------
    /**
     * Returns the duration of the pause in this {@link Step} (in ms)
     *
     * @return the duration of the pause in this {@link Step}
     */
    public long pauseDuration() {

        return pauseDuration_;
    }

    // ------------------------------------------------------------
    /**
     * Returns the duration of this {@link Step} (flight duration + pause
     * duration, in ms)
     *
     * @return the duration of this {@link Step}
     */
    public long stepDuration() {

        return flightDuration_ + pauseDuration_;
    }

    // ------------------------------------------------------------
    /**
     * Returns the flight speed during this {@link Step} (in m/s)
     *
     * @return the flight speed during this {@link Step}
     */
    public double speed() {

        return speed_;
    }

    // ------------------------------------------------------------
    /**
     * Returns true if this step defines an ongoing flight at the specified time
     * (i.e. timeOfDeparture < time < timeOfArrival), false otherwise (time
     * expressed as EPOCH in ms)
     *
     * @return true if this step defines an ongoing flight mode at the specified
     * time
     */
    public boolean isMoving(long time) {

        return ((time > timeOfDeparture_)
                && (time < timeOfArrival_));
    }

    // ---------------------------------------------
    /**
     * Returns the position determined by this step at the specified time. This
     * position is computed based on the flight speed and on the departure and
     * arrival positions if the specified if timeOfDeparture < time <
     * timeOfArrival. Otherwise the position is assumed to be the departure or
     * the arrival position, depending on whether the specified time is before
     * or after the flight. (time expressed as EPOCH in ms)
     *
     * @return the position determined by this step at the specified time
     */
    public CoordCar getPosition(long time) {

        if (time <= timeOfDeparture_) // Should not happen!
        {
            return departure_;
        }
        if (time >= timeOfArrival_) {
            return arrival_;
        }
        if (speed_ == 0.0) {
            return departure_;
        }

        double dX = (arrival_.x - departure_.x);
        double dY = (arrival_.y - departure_.y);
        long elapsed = time - timeOfDeparture_;
        double ratio = (double) elapsed / (double) flightDuration_;
        double x = departure_.x + dX * ratio;
        double y = departure_.y + dY * ratio;
        CoordCar result = new CoordCar(x, y);

        return result;
    }

    // ------------------------------------------------------------
    /**
     * Returns a representation of this step as a {@link String}
     *
     * @return a representation of this step as a {@link String}
     */
    @Override
    public String toString() {

        return "Step(departure=" + departure_
                + ",TOD=" + timeOfDeparture_
                + ",arrival=" + arrival_
                + ",TOA=" + timeOfArrival_
                + ",TOC=" + timeOfCompletion()
                + ",speed=" + speed_
                + ",distance=" + distance_
                + ",flightDuration=" + flightDuration_
                + ",pauseDuration=" + pauseDuration_;
    }

    // ------------------------------------------------------------
    public static void main(String[] args) {

        try {
            Step fl = new Step(new CoordCar(0, 0), new CoordCar(100, 100),
                    5, 14.14, 20);
            System.out.println(fl);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
