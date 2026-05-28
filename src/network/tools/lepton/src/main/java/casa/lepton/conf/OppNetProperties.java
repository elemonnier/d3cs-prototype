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
import casa.util.conf.ConfigurationProperties;
import casa.lepton.OppNetGraphDGS;
import casa.lepton.OppNetGraphWalk;
import casa.lepton.OppNetRules;
import static casa.lepton.conf.OppNetPropertyKey.ACCEL;
import static casa.lepton.conf.OppNetPropertyKey.BACKGROUND_AREA;
import static casa.lepton.conf.OppNetPropertyKey.BACKGROUND_GRAPH;
import static casa.lepton.conf.OppNetPropertyKey.BACKGROUND_IMAGE;
import static casa.lepton.conf.OppNetPropertyKey.CONNECTIVITY_PROFILES;
import static casa.lepton.conf.OppNetPropertyKey.DEFAULT_CONNECTIVITY_TYPE;
import static casa.lepton.conf.OppNetPropertyKey.DURATION;
import static casa.lepton.conf.OppNetPropertyKey.EDGE_DEFAULT_STATUS;
import static casa.lepton.conf.OppNetPropertyKey.HIDDEN_EDGES;
import static casa.lepton.conf.OppNetPropertyKey.HUB_LATENCY;
import static casa.lepton.conf.OppNetPropertyKey.HUB_PERIOD;
import static casa.lepton.conf.OppNetPropertyKey.IN_DGS;
import static casa.lepton.conf.OppNetPropertyKey.IN_HIST;
import static casa.lepton.conf.OppNetPropertyKey.LEPTON_CONSOLE_PORT;
import static casa.lepton.conf.OppNetPropertyKey.LEPTON_HOST;
import static casa.lepton.conf.OppNetPropertyKey.LEPTON_HUB_PORT;
import static casa.lepton.conf.OppNetPropertyKey.LOG_DIR;
import static casa.lepton.conf.OppNetPropertyKey.MAKE_EDGES;
import static casa.lepton.conf.OppNetPropertyKey.MANUAL;
import static casa.lepton.conf.OppNetPropertyKey.NODES;
import static casa.lepton.conf.OppNetPropertyKey.NODES_HIST;
import static casa.lepton.conf.OppNetPropertyKey.OPPNET_ADAPTER_CLASSNAME;
import static casa.lepton.conf.OppNetPropertyKey.OPPNET_RULES;
import static casa.lepton.conf.OppNetPropertyKey.OUT_DGS;
import static casa.lepton.conf.OppNetPropertyKey.PERIOD;
import static casa.lepton.conf.OppNetPropertyKey.RESOLUTION;
import static casa.lepton.conf.OppNetPropertyKey.SHOW;
import static casa.lepton.conf.OppNetPropertyKey.SIMUL_AREA;
import static casa.lepton.conf.OppNetPropertyKey.STACK_IMAGES;
import static casa.lepton.conf.OppNetPropertyKey.REF_TIME;
import static casa.lepton.conf.OppNetPropertyKey.START_TIME;
import static casa.lepton.conf.OppNetPropertyKey.STYLESHEET;
import static casa.lepton.conf.OppNetPropertyKey.STYLESHEET_FILE;
import static casa.lepton.conf.OppNetPropertyKey.TIME_BGCOLOR;
import static casa.lepton.conf.OppNetPropertyKey.TIME_CORNER;
import static casa.lepton.conf.OppNetPropertyKey.TIME_FGCOLOR;
import static casa.lepton.conf.OppNetPropertyKey.TIME_FONT;
import static casa.lepton.conf.OppNetPropertyKey.VIDEO_IMG_DIR;
import static casa.lepton.conf.OppNetPropertyKey.VIDEO_IMG_PREFIX;
import static casa.lepton.conf.OppNodePropertyKey.NODES_PROFILES;
import static casa.lepton.conf.OppNodePropertyKey.NODE_DEFAULT_STATUS;
import casa.lepton.hub.OppNetAdapter;
import casa.lepton.ui.Corner;
import casa.util.geom.AreaCar;
import java.awt.Color;
import java.awt.Font;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Typed properties used by the graph and loaded from a configuration file where
 * the property keys are those of the {@link PropertyKey} enumeration in
 * downcase characters.
 *
 * In addition, this class provides the properties common to all the nodes,
 * loaded from the same configuration file as the graph properties (see
 * {@link #getOppNodeProperties()})
 *
 */
public class OppNetProperties extends ConfigurationProperties {

    public static final String DEFAULT_CONF_FILENAME = "conf/lepton.conf";

    // the defined keys
    private static final PropertyKey[] KEYS = {
        LOG_DIR, MANUAL, IN_HIST, ACCEL, REF_TIME, SIMUL_AREA, OPPNET_RULES, EDGE_DEFAULT_STATUS, NODE_DEFAULT_STATUS, CONNECTIVITY_PROFILES,
        OPPNET_ADAPTER_CLASSNAME, HUB_PERIOD, HUB_LATENCY, LEPTON_HOST, LEPTON_HUB_PORT,
        LEPTON_CONSOLE_PORT, IN_DGS, MAKE_EDGES, NODES, PERIOD, DURATION, OUT_DGS,
        SHOW, STYLESHEET_FILE, STYLESHEET, HIDDEN_EDGES,
        BACKGROUND_GRAPH, BACKGROUND_IMAGE, BACKGROUND_AREA, TIME_CORNER, TIME_FONT, TIME_FGCOLOR, TIME_BGCOLOR,
        VIDEO_IMG_DIR, VIDEO_IMG_PREFIX, STACK_IMAGES, RESOLUTION};

    //-------------------------------------------------------------------------
    /**
     * Initialize properties from command line arguments in the form key=value
     * or conf=confFilename
     *
     * @param args the command line arguments
     */
    public OppNetProperties(String[] args) {
        this(args, null);
    }

    //-------------------------------------------------------------------------
    /**
     * Initialize properties from command line arguments in the form key=value
     * or conf=confFilename
     *
     * @param args the command line arguments
     * @param confFilename
     */
    public OppNetProperties(String[] args, String confFilename) {
        super(args, Arrays.asList(KEYS));
        if (confFilename != null) {
            try {
                // add properties from the given file, without overwritting the custom properties in args
                addProperties(confFilename, false);
            } catch (IOException ex) {
                System.err.println("Failed to load default properties from " + confFilename);
            }
        }
        try {
            // add default properties, without overwritting the custom properties
            addProperties(DEFAULT_CONF_FILENAME, false);
        } catch (IOException ex) {
            System.err.println("Failed to load default properties from " + DEFAULT_CONF_FILENAME);
        }
        expandVariables(properties);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the node properties common to all the nodes, loaded from the same
     * configuration file as the graph properties
     *
     * @return the node common properties
     */
    public OppNodeProperties getOppNodeProperties() {
        return new OppNodeProperties(properties);
    }

    //-------------------------------------------------------------------------
    @Override
    protected Object getTypedValue(PropertyKey key) {
        if (key == LOG_DIR) {
            return getLogDirectory();
        }
        if (key == MANUAL) {
            return isManual();
        }
        if (key == IN_HIST) {
            return getInHist();
        }
        if (key == ACCEL) {
            return getAccel();
        }
        if (key == REF_TIME) {
            return getRefTime();
        }
        if (key == SIMUL_AREA) {
            return getSimulArea();
        }
        if (key == OPPNET_RULES) {
            return getOppNetRules();
        }
        if (key == EDGE_DEFAULT_STATUS) {
            return getEdgeDefaultStatus();
        }
        if (key == NODE_DEFAULT_STATUS) {
            return getNodeDefaultStatus();
        }
        if (key == DEFAULT_CONNECTIVITY_TYPE) {
            return getDefaultConnectivityType();
        }
        if (key == CONNECTIVITY_PROFILES) {
            return getConnectivityProfiles();
        }
        if (key == LEPTON_HOST) {
            return getHost();
        }
        if (key == LEPTON_HUB_PORT) {
            return getHubPort();
        }
        if (key == HUB_LATENCY) {
            return getHubLatency();
        }
        if (key == HUB_PERIOD) {
            return getHubPeriod();
        }
        if (key == OPPNET_ADAPTER_CLASSNAME) {
            return getOppNetAdapter();
        }
        if (key == LEPTON_CONSOLE_PORT) {
            return getConsolePort();
        }
        if (key == IN_DGS) {
            return getInDgs();
        }
        if (key == MAKE_EDGES) {
            return makeEdges();
        }
        if (key == NODES) {
            return getNodes();
        }
        if (key == PERIOD) {
            return getPeriod();
        }
        if (key == DURATION) {
            return getDuration();
        }
        if (key == OUT_DGS) {
            return getDgsWriter();
        }
        if (key == SHOW) {
            return isShow();
        }
        if (key == STYLESHEET_FILE) {
            return getStylesheetReader();
        }
        if (key == STYLESHEET && getStylesheetReader() == null) {
            return getStylesheet();
        }
        if (key == HIDDEN_EDGES) {
            return getHiddenEdges();
        }
        if (key == BACKGROUND_GRAPH) {
            return getBackgroundGraph();
        }
        if (key == BACKGROUND_IMAGE) {
            return getBackgroundImage();
        }
        if (key == BACKGROUND_AREA) {
            return getBackgroundArea();
        }
        if (key == TIME_CORNER) {
            return getTimeCorner();
        }
        if (key == TIME_FONT) {
            return getTimeFont();
        }
        if (key == TIME_FGCOLOR) {
            return getTimeFgColor();
        }
        if (key == TIME_BGCOLOR) {
            return getTimeBgColor();
        }
        if (key == VIDEO_IMG_DIR) {
            return getVideoImgDir();
        }
        if (key == VIDEO_IMG_PREFIX) {
            return getVideoImgPrefix();
        }
        if (key == STACK_IMAGES) {
            return getStackImages();
        }
        if (key == RESOLUTION) {
            return getResolution();
        }

        return null;
    }

    public File getLogDirectory() {
        return getFileProperty(LOG_DIR);
    }

    //-------------------------------------------------------------------------
    // Start times
    //-------------------------------------------------------------------------
    /**
     * Give the time when LEPTON should start (absolute, in ms)
     *
     * @return the time when LEPTON should start
     */
    public long getLeptonStartTime() {
        return getLongProperty(START_TIME);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the ';' separated list of node_start_step,node_end_step,node_id
     *
     * @return nodes history
     */
    public String getNodesHist() {
        String hist = getProperty(NODES_HIST);
        if (hist == null) {
            BufferedReader inHist = getInHist();
            if (inHist != null) {
                StringBuilder builder = new StringBuilder();
                try {
                    String line = inHist.readLine();
                    while (line != null) {
                        if (!line.startsWith("#")) {
                            String nodeHist = line.replaceAll(" ", ",");
                            builder.append(nodeHist).append(";");
                        }
                        line = inHist.readLine();
                    }
                } catch (IOException ex) {
                    System.err.println("Error while reading history from " + getProperty(IN_HIST));
                }
                hist = builder.toString();
            }
        }
        return hist;
    }

    //-------------------------------------------------------------------------
    // Simulation properties
    //-------------------------------------------------------------------------
    /**
     * Return true if the edges must be set 'manually'
     *
     * @return true if the edges must be set 'manually'
     */
    public boolean isManual() {
        return getBooleanProperty(MANUAL);
    }

    /**
     * Give a reader to the file that contains an history, composed of lines in
     * the form: "start_step end_step duration node_id", where start and end
     * steps are in ms
     *
     * @return a reader to the history file
     */
    public BufferedReader getInHist() {
        return getReaderProperty(IN_HIST);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the acceleration of the simulation. The value 1 means realtime
     * simulation; a value greater than 1 means faster simulation; a value less
     * than 1 means slower; the value 0 means full speed (no wait between two
     * steps)
     *
     * @return acceleration of the simulation
     */
    public double getAccel() {
        return getDoubleProperty(ACCEL);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the reference virtual time (in ms), i.e. the virtual time at the
     * beginning of the simulation
     *
     * @return the reference virtual time
     */
    public long getRefTime() {
        return getLongProperty(REF_TIME);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the simulation area
     *
     * @return the simulation area
     */
    public AreaCar getSimulArea() {
        return getAreaProperty(SIMUL_AREA);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the class that extends {@link casa.lepton.OppNetRules} and defines
     * the network rules
     *
     * @return the class that extends casa.lepton.NetworkRules and defines the
     * network rules
     */
    public OppNetRules getOppNetRules() {
        Class clazz = getClassProperty(OPPNET_RULES);
        if (clazz != null) {
            try {
                return (OppNetRules) clazz.newInstance();
            } catch (Exception ex) {
                System.err.println("Failed to instanciate the " + getProperty(OPPNET_RULES) + " class");
                ex.printStackTrace();
            }
        }
        return null;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the default status of a edge if no status is supplied when it is
     * created
     *
     * @return the edge default status
     */
    public String getEdgeDefaultStatus() {
        return getProperty(EDGE_DEFAULT_STATUS);
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
    /**
     * Give the default status of a edge if no status is supplied when it is
     * created
     *
     * @return the edge default status
     */
    public String getDefaultConnectivityType() {
        return getProperty(DEFAULT_CONNECTIVITY_TYPE);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the connectivity profiles and their characteristics
     *
     * @return the connectivity profiles and their characteristics
     */
    public ConnectivityProfiles getConnectivityProfiles() {
        BufferedReader reader = getReaderProperty(CONNECTIVITY_PROFILES);
        if (reader != null) {
            try {
                ConnectivityProfiles profiles = new ConnectivityProfiles(reader);
                reader.close();
                return profiles;
            } catch (IOException ex) {
                System.err.println("Error while loading connectivity types from " + NODES_PROFILES);
                ex.printStackTrace();
            }
        }
        return new ConnectivityProfiles(properties);
    }

    //-------------------------------------------------------------------------
    // Hub properties
    //-------------------------------------------------------------------------
    public String getHost() {
        return getProperty(LEPTON_HOST);
    }

    public int getHubPort() {
        return getIntProperty(LEPTON_HUB_PORT);
    }

    public long getHubLatency() {
        return getLongProperty(HUB_LATENCY);
    }

    public long getHubPeriod() {
        return getLongProperty(HUB_PERIOD);
    }

    public OppNetAdapter getOppNetAdapter() {
        Class adapterClass = getClassProperty(OPPNET_ADAPTER_CLASSNAME);
        if (adapterClass != null) {
            try {
                Object instance = adapterClass.newInstance();
                if (instance instanceof OppNetAdapter) {
                    return (OppNetAdapter) instance;
                }
            } catch (Exception ex) {
                System.err.println("Failed to create an instance of the class " + getProperty(OPPNET_ADAPTER_CLASSNAME));
                ex.printStackTrace();
            }
        }
        return null;
    }

    //-------------------------------------------------------------------------
    // Console properties
    //-------------------------------------------------------------------------
    /**
     * Give the console port to access the network graph. If the console port is
     * 0, no console is opened
     *
     * @return console port to access the network graph
     */
    public int getConsolePort() {
        return getIntProperty(LEPTON_CONSOLE_PORT);
    }

    //-------------------------------------------------------------------------
    // {@link OppNetGraphDGS} properties
    //-------------------------------------------------------------------------
    /**
     * Give the name of the DGS input file that defines the nodes mobility [and
     * contacts]
     *
     * @return DGS input filename
     */
    public String getInDgs() {
        return getProperty(IN_DGS);
    }

    /**
     * Return true if the nodes mobility is read from an input DGS and the edges
     * representing the contacts must be computed during the simulation. Only
     * used by the {@link OppNetGraphDGS} class
     *
     * @return true if the edges representing the contacts must be computed
     * during the simulation
     */
    public boolean makeEdges() {
        return getBooleanProperty(MAKE_EDGES);
    }

    //-------------------------------------------------------------------------
    // {@link OppNetGraphWalk} properties
    //-------------------------------------------------------------------------
    /**
     * Give the number of nodes
     *
     * @return the number of nodes
     */
    public int getNbNodes() {
        if (hasProperty(NODES)) {
            String str = getProperty(NODES);
            try {
                return Integer.parseInt(str);
            } catch (NumberFormatException e) {
                Map<String, Integer> nodes = getNodes();
                if (nodes != null) {
                    int sum = 0;
                    for (int nb : nodes.values()) {
                        sum += nb;
                    }
                    return sum;
                }
                System.err.println("Failed to load the number of nodes from the " + str);
            }
        }
        return 0;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the number of nodes for each profile name.
     *
     * @return pairs (profile name, nb nodes)
     */
    public Map<String, Integer> getNodes() {

        if (hasProperty(NODES)) {

            try {

                // try to parse the property as an integer
                Integer.parseInt(getProperty(NODES));
                return new HashMap<>();

            } catch (NumberFormatException e) {

                // try to parse the property as a map
                Map<String, String> map = getMapProperty(NODES);
                if (map != null && !map.isEmpty()) {
                    if (getProperty(NODES_PROFILES) == null) {
                        System.err.println("Warning: no \"" + NODES_PROFILES + "\" property provided, "
                                + "mandatory with the \"" + NODES + "\" property");
                    }
                    Map<String, Integer> nodes = new HashMap<>();
                    for (String key : map.keySet()) {
                        nodes.put(key, Integer.parseInt(map.get(key)));
                    }
                    return nodes;
                }
            }
        }
        return null;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the network refresh period (in ms), ie the period between the
     * simulation steps. Only used by the {@link OppNetGraphWalk} class
     *
     * @return network refresh period
     */
    public long getPeriod() {
        return (long) (getDoubleProperty(PERIOD) * 1000);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the duration of the simulation (in ms). If the value is -1, the
     * duration of the simulation is unlimited. Only used by the
     * {@link OppNetGraphWalk} class
     *
     * @return the duration of the simulation
     */
    public long getDuration() {
        return getLongProperty(DURATION) * 1000;
    }

    //-------------------------------------------------------------------------
    // DGS output properties
    //-------------------------------------------------------------------------
    /**
     * Give a writer to the DGS log of the dynamic graph produced during the
     * simulation
     *
     * @return a writer to the DGS log of the simulation dynamic graph
     */
    public PrintWriter getDgsWriter() {
        return getWriterProperty(OUT_DGS);
    }

    //-------------------------------------------------------------------------
    // Vizualisation properties
    //-------------------------------------------------------------------------
    /**
     * Return true if the graph should be displayed during simulation
     *
     * @return true if the graph should be displayed during simulation
     */
    public boolean isShow() {
        return getBooleanProperty(SHOW);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the stylesheet that defines the appearance of the graph
     *
     * @return the stylesheet
     */
    public BufferedReader getStylesheetReader() {
        return getReaderProperty(STYLESHEET_FILE);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the stylesheet that defines the appearance of the graph
     *
     * @return the stylesheet
     */
    public String getStylesheet() {
        BufferedReader reader = getStylesheetReader();
        if (reader != null) {
            try {
                // read lines from input stream and produce a string
                StringBuilder buffer = new StringBuilder();
                String line = reader.readLine();
                while (line != null) {
                    buffer.append(line).append(" ");
                    line = reader.readLine();
                }
                reader.close();
                return buffer.toString();
            } catch (IOException ex) {
                ex.printStackTrace();
                System.err.println("Failed to load the stylesheet from " + getProperty(STYLESHEET));
            }
        }

        return getProperty(STYLESHEET);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the connectivitytypes and/or status for which the edges are hidden
     *
     * @return connectivity types and/or status for which the edges are hidden
     */
    public Set<String> getHiddenEdges() {
        return getSetProperty(HIDDEN_EDGES);
    }

    //-------------------------------------------------------------------------
    // Background properties
    //-------------------------------------------------------------------------
    /**
     * Give the name of the DGS file that defines a graph to be displayed as
     * background
     *
     * @return the DGS filename that defines a graph to be displayed as
     * background
     */
    public String getBackgroundGraph() {
        return getProperty(BACKGROUND_GRAPH);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the background image
     *
     * @return the background image
     */
    public File getBackgroundImage() {
        return getFileProperty(BACKGROUND_IMAGE);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the background image or graph area
     *
     * @return the background area
     */
    public AreaCar getBackgroundArea() {
        return getAreaProperty(BACKGROUND_AREA);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the location of the block that contains the time in the frame
     *
     * @return the location of the block that contains the time in the frame
     */
    public Corner getTimeCorner() {
        String str = getProperty(TIME_CORNER);
        if (str != null) {
            return Corner.getCorner(str);
        }
        return null;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the font of the time in the frame
     *
     * @return the font of the time
     */
    public Font getTimeFont() {
        String str = getProperty(TIME_FONT);
        if (str != null) {
            return Font.decode(str);
        }
        return null;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the foreground color of the time in the frame
     *
     * @return foreground color of the time
     */
    public Color getTimeFgColor() {
        return getColorProperty(TIME_FGCOLOR);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the background color of the time in the frame
     *
     * @return background color of the time
     */
    public Color getTimeBgColor() {
        return getColorProperty(TIME_BGCOLOR);
    }

    //-------------------------------------------------------------------------
    // Video output properties
    //-------------------------------------------------------------------------
    /**
     * Give the directory where output images will be stored
     *
     * @return the directory where output images will be stored
     */
    public File getVideoImgDir() {
        return getFileProperty(VIDEO_IMG_DIR);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the prefix of the output images filenames
     *
     * @return the prefix of the output images filenames
     */
    public String getVideoImgPrefix() {
        return getProperty(VIDEO_IMG_PREFIX);
    }

    //-------------------------------------------------------------------------
    /**
     * Return true to avoid superposition of images if the background is
     * transparent
     *
     * @return true to avoid superposition of images
     */
    public boolean getStackImages() {
        return getBooleanProperty(STACK_IMAGES);
    }

    //-------------------------------------------------------------------------
    /**
     * Give the resolution of the output images
     *
     * @return the resolution of the output images
     */
    public String getResolution() {
        return getProperty(RESOLUTION);
    }
}
