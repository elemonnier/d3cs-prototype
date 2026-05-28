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

import java.util.regex.Pattern;
import casa.util.conf.PropertyKey;
import casa.util.conf.ConfigurationProperties;
import static casa.lepton.conf.OppNetPropertyKey.DEFAULT_CONNECTIVITY_TYPE;
import static casa.lepton.conf.OppNodePropertyKey.ALPHA;
import static casa.lepton.conf.OppNodePropertyKey.BETA;
import static casa.lepton.conf.OppNodePropertyKey.COORD;
import static casa.lepton.conf.OppNodePropertyKey.GRAPH;
import static casa.lepton.conf.OppNodePropertyKey.JOURNEYS_DIR;
import static casa.lepton.conf.OppNodePropertyKey.JOURNEYS_FILE;
import static casa.lepton.conf.OppNodePropertyKey.K;
import static casa.lepton.conf.OppNodePropertyKey.LABEL;
import static casa.lepton.conf.OppNodePropertyKey.MAX_DIST;
import static casa.lepton.conf.OppNodePropertyKey.MAX_SPEED;
import static casa.lepton.conf.OppNodePropertyKey.MAX_WAIT;
import static casa.lepton.conf.OppNodePropertyKey.MIN_DIST;
import static casa.lepton.conf.OppNodePropertyKey.MIN_SPEED;
import static casa.lepton.conf.OppNodePropertyKey.MIN_WAIT;
import static casa.lepton.conf.OppNodePropertyKey.MOBILE;
import static casa.lepton.conf.OppNodePropertyKey.NODES_PROFILES;
import static casa.lepton.conf.OppNodePropertyKey.NODE_DEFAULT_STATUS;
import static casa.lepton.conf.OppNodePropertyKey.NODE_LABELS;
import static casa.lepton.conf.OppNodePropertyKey.PREFIX;
import static casa.lepton.conf.OppNodePropertyKey.PAUSE_TYPE;
import static casa.lepton.conf.OppNodePropertyKey.RHO;
import static casa.lepton.conf.OppNodePropertyKey.SEED;
import static casa.lepton.conf.OppNodePropertyKey.SHOW_NODE_STATUS;
import static casa.lepton.conf.OppNodePropertyKey.SUPPORTED_CONNECTIVITY;
import static casa.lepton.conf.OppNodePropertyKey.TAG;
import static casa.lepton.conf.OppNodePropertyKey.WALK_AREA;
import static casa.lepton.conf.OppNodePropertyKey.WALK_CLASS;
import casa.lepton.walk.Walk;
import casa.util.geom.AreaCar;
import casa.util.geom.CoordCar;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * Properties used for the graph nodes: different nodes may have different
 * properties.
 *
 */
public class OppNodeProperties extends ConfigurationProperties {

    // the defined keys
    private static final PropertyKey[] KEYS = {
        NODES_PROFILES, SUPPORTED_CONNECTIVITY,
        NODE_LABELS, LABEL, TAG, MOBILE, SHOW_NODE_STATUS,
        WALK_CLASS, WALK_AREA, COORD,
        PREFIX,
        SEED, MIN_SPEED, MAX_SPEED, MIN_WAIT, MAX_WAIT, MIN_DIST, MAX_DIST,
        ALPHA, BETA, K, RHO, PAUSE_TYPE, GRAPH, JOURNEYS_DIR, JOURNEYS_FILE
    };

    //-------------------------------------------------------------------------
    /**
     * Initializes default properties from the given properties
     *
     * @param properties the default properties string values
     */
    public OppNodeProperties(Properties properties) {
        super(properties, Arrays.asList(KEYS));
        expandVariables(properties);
    }

    //-------------------------------------------------------------------------
    @Override
    protected Object getTypedValue(PropertyKey key) {
        if (key == NODES_PROFILES) {
            return getNodeProfiles();
        } else if (key == SUPPORTED_CONNECTIVITY) {
            return getSupportedConnectivityTypes();
        } else if (key == NODE_LABELS) {
            return getNodeLabels();
        } else if (key == LABEL) {
            return getLabel();
        } else if (key == TAG) {
            return getTag();
        } else if (key == SHOW_NODE_STATUS) {
            return getShowNodeStatus();
        } else if (key == WALK_CLASS) {
            return getWalk();
        } else if (key == WALK_AREA) {
            return getWalkArea();
        } else if (key == MOBILE) {
            return isMobile();
        } else if (key == COORD) {
            return getCoord();
        } else if (key == PREFIX) {
            return getPrefix();
        } else if (key == SEED) {
            return getSeed();
        } else if (key == MIN_SPEED) {
            return getMinSpeed();
        } else if (key == MAX_SPEED) {
            return getMaxSpeed();
        } else if (key == MIN_WAIT) {
            return getMinWait();
        } else if (key == MAX_WAIT) {
            return getMaxWait();
        } else if (key == MIN_DIST) {
            return getMinDist();
        } else if (key == MAX_DIST) {
            return getMaxDist();
        } else if (key == ALPHA) {
            return getAlpha();
        } else if (key == BETA) {
            return getBeta();
        } else if (key == K) {
            return getK();
        } else if (key == RHO) {
            return getRho();
        } else if (key == PAUSE_TYPE) {
            return getPauseType();
        } else if (key == GRAPH) {
            return getGraph();
        } else if (key == JOURNEYS_DIR) {
            return getJourneysDirectory();
        } else if (key == JOURNEYS_FILE) {
            return getJourneysFilename();
            //        } else if (key == APP_SCENARIO) {
            //            return getAppScenario();
            //        } else if (key == APP_LOG_FILE) {
            //            return getApplicationLogReader();
        }
        return null;
    }

    //-------------------------------------------------------------------------
    // Node profiles & connectivity
    //-------------------------------------------------------------------------
    /**
     * Give the nodes profiles and their characteristics
     *
     * @return the nodes profiles and their characteristics
     */
    public OppNodeProfiles getNodeProfiles() {
        BufferedReader reader = getReaderProperty(NODES_PROFILES);
        if (reader != null) {
            try {
                return new OppNodeProfiles(this, reader);
            } catch (IOException ex) {
                ex.printStackTrace();
                System.err.println("Error while loading profiles from " + getProperty(NODES_PROFILES));
            }
        }
        return null;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the connectivity types supported by the node
     *
     * @return the connectivity types supported by the node
     */
    public Set<String> getSupportedConnectivityTypes() {
        Set<String> types = getSetProperty(SUPPORTED_CONNECTIVITY);
        if (types == null) {
            types = new HashSet<>();
        }
        if (types.isEmpty()) {
            String defaultType = getProperty(DEFAULT_CONNECTIVITY_TYPE);
            if (defaultType != null) {
                types.add(defaultType);
            }
        }
        return types;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the default status of a node if no status is supplied when it is
     * created
     *
     * @return the node default status
     */
    public String getNodeDefaultStatus() {
        return getProperty(NODE_DEFAULT_STATUS);
    }

    //-------------------------------------------------------------------------
    // Vizualisation
    //-------------------------------------------------------------------------
    /**
     * Give the label of the node
     *
     * @return the label of the node
     */
    public NodeLabels getNodeLabels() {
        BufferedReader reader = getReaderProperty(NODE_LABELS);
        if (reader != null) {
            try {
                return new NodeLabels(reader);
            } catch (IOException ex) {
                ex.printStackTrace();
                System.err.println("Error while loading labels from " + getProperty(NODE_LABELS));
            }
        }
        return null;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the label of the node
     *
     * @return the label of the node
     */
    public String getLabel() {
        return getProperty(LABEL);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the tag for the node
     *
     * @return the tag for the node
     */
    public String getTag() {
        return getProperty(TAG);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the connectivity type for which the node status is shown
     *
     * @return the connectivity type for which the node status is shown
     */
    public String getShowNodeStatus() {
        return getProperty(SHOW_NODE_STATUS);
    }

    //-------------------------------------------------------------------------
    // Mobility
    //-------------------------------------------------------------------------
    /**
     * Give
     *
     * @return the class used to define the mobility model of the node
     */
    public Walk getWalk() {
        Class<?> clazz = getClassProperty(WALK_CLASS);
        if (clazz != null) {
            try {
                Method method_ = clazz.getMethod("getDefault", OppNodeProperties.class);
                return (Walk) method_.invoke(null, this);
            } catch (Exception ex) {
                ex.printStackTrace();
                System.err.println("Failed to create default " + clazz.getName() + " instance");
            }
        }
        return null;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the node simulation area
     *
     * @return the node simulation area
     */
    public AreaCar getWalkArea() {
        return getAreaProperty(WALK_AREA);
    }

    //-------------------------------------------------------------------------
    /**
     * Return true if the node is mobile
     *
     * @return true if the node is mobile
     */
    public boolean isMobile() {
        return getBooleanProperty(MOBILE);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the initial location of the node
     *
     * @return the initial location of the node
     */
    public CoordCar getCoord() {
        return getCoordProperty(COORD);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the seed to initialize the random values generator.
     *
     * @return the seed to initialize the random values generator
     */
    public long getSeed() {
        if (hasProperty(SEED)) {
            return getLongProperty(SEED);
        }
        return System.currentTimeMillis();
    }

    //-------------------------------------------------------------------------
    /**
     * Give the prefix for the node ids to conform to the current properties.
     *
     * @return the node ids prefix
     */
    public String getPrefix() {
        return getProperty(PREFIX);
    }

    //-------------------------------------------------------------------------
    // GraphWalk & RandomWayPoint & LevyWalk
    //-------------------------------------------------------------------------
    /**
     *
     * @return the minimum speed of the node (in m/s)
     */
    public double getMinSpeed() {
        return getDoubleProperty(MIN_SPEED);
    }

    //-------------------------------------------------------------------------*
    /**
     *
     * @return the maximum speed of the node (in m/s)
     */
    public double getMaxSpeed() {
        return getDoubleProperty(MAX_SPEED);
    }

    //-------------------------------------------------------------------------
    /**
     *
     * @return the minimum wait duration of the node after each flight (in ms)
     */
    public long getMinWait() {
        return getLongProperty(MIN_WAIT) * 1000;
    }

    //-------------------------------------------------------------------------
    /**
     *
     * @return the maximum wait duration of the node after each flight (in ms)
     */
    public long getMaxWait() {
        return getLongProperty(MAX_WAIT) * 1000;
    }

    //-------------------------------------------------------------------------
    // LevyWalk
    //-------------------------------------------------------------------------
    /**
     * Give the minimum distance of a flight (in m)
     *
     * @return the minimum distance of a flight (in m)
     */
    public double getMinDist() {
        return getDoubleProperty(MIN_DIST);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the maximum distance of a flight (in m)
     *
     * @return the maximum distance of a flight (in m)
     */
    public double getMaxDist() {
        return getDoubleProperty(MAX_DIST);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the Levy Alpha parameter
     *
     * @return the Levy Alpha parameter
     */
    public double getAlpha() {
        return getDoubleProperty(ALPHA);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the Levy Beta parameter
     *
     * @return the Levy Beta parameter
     */
    public double getBeta() {
        return getDoubleProperty(BETA);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the Levy K parameter
     *
     * @return the Levy K parameter
     */
    public double getK() {
        return getDoubleProperty(K);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the Levy Rho Levy parameter
     *
     * @return the Levy Rho Levy parameter
     */
    public double getRho() {
        return getDoubleProperty(RHO);
    }

    //-------------------------------------------------------------------------
    // GraphWalk
    //-------------------------------------------------------------------------
    /**
     * Give a string representation of the pause type (???)
     *
     * @return string representation of the pause type (???)
     */
    public String getPauseType() {
        return getProperty(PAUSE_TYPE);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the geo-referenced graph along which the node walks
     *
     * @return geo-referenced graph along which the node walks
     */
    public File getGraph() {
        return getFileProperty(GRAPH);
    }

    //-------------------------------------------------------------------------
    // BusWalk
    //-------------------------------------------------------------------------
    /**
     * Give the directory that contains the journeys file and the paths files
     *
     * @return the directory that contains the journeys file and the paths files
     */
    public File getJourneysDirectory() {
        return getFileProperty(JOURNEYS_DIR);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the journeys file
     *
     * @return the journeys file
     */
    public String getJourneysFilename() {
        return getProperty(JOURNEYS_FILE);
    }
}
