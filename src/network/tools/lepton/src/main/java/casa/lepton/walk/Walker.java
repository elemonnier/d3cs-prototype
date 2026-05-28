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
 * A {@link Walker} characterizes a mobile element that moves according to a
 * certain kind of {@link Walk}.
 */
public interface Walker {

    /**
     * Returns an {@link Walk} object that defines the mobility model of this
     * {@link Walker}.
     *
     * @return the kind of {@link Walk} of this {@link Walker}.
     */
    public Walk getWalk();

    /**
     * Returns a {@link CoordCar} object that defines the position of this
     * {@link Walker} at the specified time.
     *
     * @param time the time for which the position is requested
     * @return the position of this {@link Walker} at the specified time
     */
    public CoordCar getPosition(long time);

    /**
     * Returns a {@link Step} object that defines the current step of this
     * {@link Walker}.
     *
     * @return the current {@link Step} of this {@link Walker}.
     */
    public Step getStep();

    /**
     * Returns a {@link Step} object that defines the next step of this
     * {@link Walker}.
     *
     * @return the next {@link Step} of this {@link Walker}.
     */
    public Step nextStep();

}
