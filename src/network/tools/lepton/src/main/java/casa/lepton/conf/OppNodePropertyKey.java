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
package casa.lepton.conf;

import casa.util.conf.PropertyKey;

/**
 * The keys used to access the properties in the {@link OppNodeProperties}
 * classe. Each key is represented in the configuration files in downcase
 * characters
 *
 */
public enum OppNodePropertyKey implements PropertyKey {
    NODES_PROFILES,
    // Connectivity
    SUPPORTED_CONNECTIVITY,
    NODE_DEFAULT_STATUS,
    // Vizualisation
    LABEL,
    TAG,
    SHOW_NODE_STATUS,
    NODE_LABELS,
    // Mobility properties
    WALK_CLASS,
    WALK_AREA,
    MOBILE,
    COORD,
    // Profile properties
    PREFIX,
    // GraphWalk & RandomWayPoint & LevyWalk & BusWalk properties
    SEED,
    MIN_SPEED,
    MAX_SPEED,
    MIN_WAIT,
    MAX_WAIT,
    // LevyWalk properties
    MIN_DIST,
    MAX_DIST,
    ALPHA,
    BETA,
    K,
    RHO,
    // GraphWalk properties
    PAUSE_TYPE,
    GRAPH,
    // BusWalk properties
    JOURNEYS_DIR,
    JOURNEYS_FILE
}
