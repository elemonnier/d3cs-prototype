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

import casa.dgs.PathLoader;
import casa.lepton.conf.OppNodeProperties;
import casa.util.geom.AreaCar;
import casa.util.geom.AreaGeo;
import casa.util.geom.CoordCar;
import casa.util.geom.CoordGeo;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.graphstream.graph.Graph;
import org.graphstream.graph.Path;

/**
 * A {@link Walk} that provides {@link BusWalker} instances for the journeys of
 * buses of a bus line. The journeys are loaded from a journeys file and the
 * paths files listed as the first line of this file in the same directory.
 * Moreover, this class has a main method used to generate a DGS file from the
 * journeys of a bus line
 *
 */
public class BusWalk implements Walk {

    private static final Map<String, BusWalk> instances = new HashMap<>();

    private Map<String, BusJourney> journeys;
//    private Iterator<BusJourney> journeys;  // the bus journeys of a line
    private final long seed;                // the seed to generate random pause times
    private AreaCar area;                      // the walk area

    /**
     * Method called to generate an instance of this class in
     * {@link OppNodeProperties#getWalk()}
     *
     * @param props the properties that contains the journeys directory and
     * filename and the seed
     * @return instance of this class
     */
    public static BusWalk getDefault(OppNodeProperties props) {
        File directory = props.getJourneysDirectory();
        String filename = props.getJourneysFilename();
        long seed = props.getSeed();
        BusWalk walk = instances.get(filename);
        if (walk == null) {
            walk = new BusWalk(seed, directory, filename);
            instances.put(filename, walk);
        }
        return walk;
    }

    /**
     * Constructor. Load the journeys
     *
     * @param seed the seed to generate random pause times
     * @param directory the directory that contains the journeys file and the
     * paths files
     * @param filename the name of the journeys file
     */
    private BusWalk(long seed, File directory, String filename) {

        this.seed = seed;
        File file = new File(directory, filename);

        try {

            BusJourneyLoader loader = new BusJourneyLoader(file.getAbsolutePath());
            List<BusJourney> journeysList = loader.getJourneys();

            this.area = loader.getArea();
            this.journeys = new HashMap<>();
            for (Iterator<BusJourney> it = journeysList.iterator(); it.hasNext();) {
                BusJourney journey = it.next();
                journeys.put(journey.getBusName(), journey);
            }

        } catch (Exception ex) {
            System.err.println("Error while loading journeys from " + file);
            ex.printStackTrace();
        }
    }

    @Override
    public AreaCar getArea() {
        return area;
    }

    @Override
    public BusWalker getWalker(long time, String nodeId) {

        BusJourney journey = journeys.get(nodeId);
        if (journey != null) {
            return new BusWalker(this, journey, seed);
        }
        return null;
    }

    //-------------------------------------------------------------------------
    // To generate journeys as a DGS file
    //-------------------------------------------------------------------------
    private static void usage() {
        System.err.println("Usage: java BusWalk [journeys_file]*");
        System.err.println("Load journeys and generate an history file");
        System.err.println("The first line of the journeys_file is a list of paths filenames");
        System.err.println("that must be in the same directory as the journeys_file");
        System.exit(-1);
    }

    public static void main(String[] args) throws IOException, ParseException {
        if (args.length == 0 || args[0].equals("-h")) {
            usage();
        }

        for (String arg : args) {
            BusJourneyLoader loader = new BusJourneyLoader(arg);
//        loader.toDGS(System.out);
            loader.toHistory(System.out);
        }
    }
}

class BusJourneyLoader {

    private final String lineName;            // the name of the bus line
    private final List<Path> paths;           // the paths that compose the bus line
    private final Graph graph;                // the graph of the paths
    private final List<BusJourney> journeys;  // the journeys

    /**
     * Constructor. Load the journeys.
     *
     * @param journeysFilename the name of the journeys file
     * @throws IOException if an error occurs while reading the input files
     * @throws ParseException if a file has a wrong format
     */
    public BusJourneyLoader(String journeysFilename) throws IOException, ParseException {
        File journeysFile = new File(journeysFilename);

        // get the paths filenames from the 1st line of the journeys file
        BufferedReader reader = new BufferedReader(new FileReader(journeysFile));
        String[] pathFiles = reader.readLine().split(" ");

        // get the line name from the prefix of the 1st filename
        String prefix = pathFiles[0].split("_")[0];
        this.lineName = prefix.substring(0, prefix.length() - 2);

        // load the path from the files in the journeys directory
        File dir = journeysFile.getParentFile();
        PathLoader loader = new PathLoader();
        paths = new ArrayList<>();
        for (String filename : pathFiles) {
            File file = new File(dir, filename);
            if (!file.exists()) {
                throw new FileNotFoundException("File " + file + " not found.");
            }
            paths.add(loader.loadPath(file.getAbsolutePath()));
        }

        // load the journeys
        graph = loader.getGraph();
        journeys = new ArrayList<>();
        BusJourney journey = BusJourney.loadJourney(graph, paths, reader);
        while (journey != null) {
            journeys.add(journey);
            journey = BusJourney.loadJourney(graph, paths, reader);
        }
        reader.close();
    }

    /**
     * Give the area loaded from the DGS graph attributes
     *
     * @return the graph area
     */
    public AreaCar getArea() {

        if (graph.hasAttribute("area")) {

            return AreaCar.fromString(graph.getAttribute("area"));

        } else if (graph.hasAttribute("width") && graph.hasAttribute("height")) {

            AreaCar area;
            double width = graph.getAttribute("width");
            double height = graph.getAttribute("height");
            if (graph.hasAttribute("x") && graph.hasAttribute("y")) {
                double x = graph.getAttribute("x");
                double y = graph.getAttribute("y");
                area = new AreaCar(x, y, width, height);
            } else {
                area = new AreaCar(width, height);
            }

            if (graph.hasAttribute("reflat") && graph.hasAttribute("reflon")) {
                double reflat = graph.getAttribute("reflat");
                double reflon = graph.getAttribute("reflon");
                area.setRef(reflat, reflon);
            } else if (graph.hasAttribute("minlat") && graph.hasAttribute("minlon")) {
                double minlat = graph.getAttribute("minlat");
                double minlon = graph.getAttribute("minlon");
                CoordGeo ref = new CoordCar(area.x, area.y).getCoordRef(minlat, minlon);
                area.setRef(ref.latitude, ref.longitude);
            }

            return area;

        } else if (graph.hasAttribute("minlat") && graph.hasAttribute("minlon") && graph.hasAttribute("maxlat") && graph.hasAttribute("maxlon")) {

            double minlat = graph.getAttribute("minlat");
            double minlon = graph.getAttribute("minlon");
            double maxlat = graph.getAttribute("maxlat");
            double maxlon = graph.getAttribute("maxlon");

            AreaGeo area = new AreaGeo(minlat, minlon, maxlat, maxlon);

            double reflat = minlat;
            double reflon = minlon;
            if (graph.hasAttribute("reflat") && graph.hasAttribute("reflon")) {
                reflat = graph.getAttribute("reflat");
                reflon = graph.getAttribute("reflon");
            }
            return area.toAreaCar(reflat, reflon);
        }
        return null;
    }

    /**
     * Give the journeys
     *
     * @return list of journeys
     */
    public List<BusJourney> getJourneys() {
        return journeys;
    }

    //-------------------------------------------------------------------------
    // Journey -> History
    //-------------------------------------------------------------------------
    public void toHistory(PrintStream out) {
        if (journeys != null) {
            // start_time end_time duration node_id node_profile
            String profile = "line" + lineName;
            for (BusJourney journey : journeys) {
                long startTime = journey.getStartTime();
                long endTime = journey.getEndTime();
                long duration = endTime - startTime;
                String busName = journey.getBusName();
                out.println(startTime + " " + endTime + " " + duration + " " + busName + ":" + profile);
            }
        }
    }

    //-------------------------------------------------------------------------
    // Journey -> DGS
    //-------------------------------------------------------------------------
    /**
     * Write the loaded journeys as DGS to the given output stream
     *
     * @param out the output stream
     */
    public void toDGS(PrintStream out) {
        if (journeys != null) {
            String busTag = "line" + lineName;
            List<DGSLine> dgsLines = new ArrayList<>();
            for (BusJourney journey : journeys) {
                toDGS(dgsLines, busTag, journey);
            }
            if (!dgsLines.isEmpty()) {
                writeHeader(out);
                DGSLine[] array = new DGSLine[dgsLines.size()];
                dgsLines.toArray(array);
                Arrays.sort(array);
                long step = -1;
                for (DGSLine line : array) {
                    if (line.time > step) {
                        step = line.time;
                        out.println("st " + step);
                    }
                    out.println(line.line);
                }
            }
        }
    }

    /**
     * Add the DGS lines to the given lines for the given bus journey
     *
     * @param dgsLines the list of lines to be completed
     * @param busTag tag to add when adding the bus node
     * @param journey the bus journey
     */
    private void toDGS(List<DGSLine> dgsLines, String busTag, BusJourney journey) {

        String busName = journey.getBusName();
        Iterator<BusJourney.BusNode> it = journey.iterator(System.currentTimeMillis());
        long step = journey.getStartTime();
        boolean added = false, offline = false;

        while (it.hasNext()) {
            BusJourney.BusNode node = it.next();
            String str = busName + " x=" + node.getX() + " y=" + node.getY();
            if (!added) {
                dgsLines.add(new DGSLine(step, "an " + str + " tag=\"" + busTag + "\""));
                added = true;
            } else {
                dgsLines.add(new DGSLine(step, "cn " + str));
            }
            long pause = node.getPauseDuration();
            if (pause > 0) {
                step += pause;
                dgsLines.add(new DGSLine(step, "cn " + str));
            }
            step = node.getNextNodeArrivalTime(step);
            // TODO set offline if too long delay
        }
        dgsLines.add(new DGSLine(journey.getEndTime() + 60000, "dn " + busName));
    }

    /**
     * Write a DGS header with the graph attributes if any
     *
     * @param writer the output stream
     */
    private void writeHeader(PrintStream out) {
        out.println("DGS004");
        out.println("null 0 0");
        String[] keys = {"x", "y", "width", "height", "minlat", "maxlat", "minlon", "maxlon"};
        String attr = "";
        for (String key : keys) {
            if (graph.hasAttribute(key)) {
                Object attribute = graph.getAttribute(key);
                if (attribute instanceof String) {
                    attr += " " + key + "=\"" + attribute + "\"";
                } else {
                    attr += " " + key + "=" + attribute + "";
                }
            }
        }
        if (!attr.equals("")) {
            out.println("cg " + attr);
        }
    }

    //-------------------------------------------------------------------------
    /**
     * A timestamped DGS line
     */
    class DGSLine implements Comparable<DGSLine> {

        private long time;   // the line step
        private String line; // the DGS line

        public DGSLine(long time, String line) {
            this.time = time;
            this.line = line;
        }

        @Override
        public int compareTo(DGSLine line) {
            if (time < line.time) {
                return -1;
            } else if (time > line.time) {
                return +1;
            }
            return 0;
        }
    }
}
