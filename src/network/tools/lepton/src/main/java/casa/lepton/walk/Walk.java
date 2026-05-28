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

import casa.util.geom.AreaCar;

/**
 * An interface that defines a mobility model for nodes moving in some area, and
 * provides general-purpose methods for handling {@link Walker} instances in
 * MobSim.
 *
 */
public interface Walk {

    /**
     * Returns the area in which this walk is defined.
     *
     * @return the {@link AreaCar} in which this walk is defined
     */
    public AreaCar getArea();

    /**
     * Returns a new {@link Walker} that will move according to the mobility
     * model implemented in this instance of {@link Walk}.
     *
     * @param time the time of creation of this walker
     * @param nodeId
     * @return a new {@link Walker}, whose mobility starts at the specified time
     */
    public Walker getWalker(long time, String nodeId);

}
