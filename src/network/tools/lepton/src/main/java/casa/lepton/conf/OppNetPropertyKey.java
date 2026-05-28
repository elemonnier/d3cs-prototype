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
 * The keys used to access the properties in the {@link OppNetProperties}
 * classe. Each key is represented in the configuration files in downcase
 * characters
 *
 */
public enum OppNetPropertyKey implements PropertyKey {
    LOG_DIR,
    // Start times
    START_TIME,
    NODES_HIST,
    // Simulation
    REF_TIME,
    MANUAL,
    IN_HIST,
    ACCEL,
    SIMUL_AREA,
    OPPNET_RULES,
    CONNECTIVITY_PROFILES,
    DEFAULT_CONNECTIVITY_TYPE,
    EDGE_DEFAULT_STATUS,
    // Hub
    LEPTON_HOST,
    LEPTON_HUB_PORT,
    HUB_LATENCY,
    HUB_PERIOD,
    OPPNET_ADAPTER_CLASSNAME,
    // Console
    LEPTON_CONSOLE_PORT,
    // OppNetGraphDGS
    IN_DGS,
    MAKE_EDGES,
    // OppNetGraphWalk
    NODES,
    PERIOD,
    DURATION,
    // DGS Output
    OUT_DGS,
    // Vizualisation
    SHOW,
    STYLESHEET_FILE,
    STYLESHEET,
    HIDDEN_EDGES,
    // Background
    BACKGROUND_GRAPH,
    BACKGROUND_IMAGE,
    BACKGROUND_AREA,
    TIME_CORNER,
    TIME_FONT,
    TIME_FGCOLOR,
    TIME_BGCOLOR,
    // Video output properties
    VIDEO_IMG_DIR,
    VIDEO_IMG_PREFIX,
    STACK_IMAGES,
    RESOLUTION,

}
