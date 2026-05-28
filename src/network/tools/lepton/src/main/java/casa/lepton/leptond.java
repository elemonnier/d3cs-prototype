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
package casa.lepton;

import casa.lepton.conf.OppNetProperties;
import casa.lepton.console.OppNetConsole;
import casa.lepton.hub.Hub;
import casa.lepton.ui.OppNetFrame;
import casa.lepton.ui.OppNetOutput;
import java.io.IOException;
import java.text.DecimalFormat;
import java.util.Map;

/**
 * A program that launches a network simulation, using a {@link OppNetGraph},
 * and a {@link OppNetConsole} to access its methods. See
 * {@link leptond#usage()} for possible options.
 *
 */
public class leptond {

    protected static final String SIMUL_NETWORKID = "SIMUL";

    protected OppNetGraph graph;
    protected OppNetConsole console;
    protected OppNetFrame frame;
    protected OppNetOutput output;
    protected Hub hub;

    protected OppNetProperties props;
    protected String dgsFile;

    // ------------------------------------------------------------------------
    private static void usage() {

        System.out.println("\nRun the LEPTON daemon...");
        System.out.println("\nArguments: [conf=confFile]* [key=value]*");
        System.out.println("    conf=confFile  configuration file defining some properties");
        System.out.println("    key=value      a configuration property\n");
        System.out.println("The configuration files and properties passed as arguments overwrite the default configuration\n");

        System.exit(1);

    }

    // ------------------------------------------------------------------------
    public static void main(String[] args) throws Exception {

        boolean startDaemon = true;
        if (args.length > 0) {
            switch (args[0]) {
                case "-h":
                    usage();
                case "info":
                    startDaemon = false;
                    String[] args_dup = new String[args.length - 1];
                    System.arraycopy(args, 1, args_dup, 0, args_dup.length);
                    args = args_dup;
            }
        }

        // load the properties
        OppNetProperties props = new OppNetProperties(args);

        // display the graph & node properties
        System.out.println("OppNet:");
        props.displayDefinedProperties();
        System.out.println("OppNodes:");
        props.getOppNodeProperties().displayDefinedProperties();
        System.out.println("Connectivity:");
        props.getConnectivityProfiles().displayDefinedProfiles();

        if (startDaemon) {
            leptond daemon = new leptond(props);
            daemon.start();
        }
    }

    // ------------------------------------------------------------------------
    public leptond(OppNetProperties props) throws Exception {

        this.props = props;
        this.dgsFile = props.getInDgs();
        this.graph = makeNetworkGraph();
        this.console = graph.getConsole();
        this.frame = graph.makeFrame();
        this.output = graph.makeOutput();
        this.hub = graph.getHub();
    }

    // ------------------------------------------------------------------------
    protected OppNetGraph makeNetworkGraph() throws IOException {
        if (props.isManual()) {
            return new OppNetGraph(SIMUL_NETWORKID, props);
        } else if (dgsFile != null) {
            return new OppNetGraphDGS(SIMUL_NETWORKID, dgsFile, props);
        } else {
            return new OppNetGraphWalk(SIMUL_NETWORKID, props);
        }
    }

    // ------------------------------------------------------------------------
    public void start() throws IOException {
//        Runtime.getRuntime().addShutdownHook(new ShutdownThread(this));

        if (frame != null) {
            frame.setVisible(true);
        }

        if (console != null) {
            console.startConsole();
        }

        if (output != null) {
            output.start();
        }

        if (hub != null) {
            hub.start();
        }

//        long begin = props.getLeptonStartTime();
//        long now = System.currentTimeMillis();
//        if (begin > now) {
//            System.out.println("Deferring start until " + TIME_FORMAT.format(begin));
//            try {
//                Thread.sleep(begin - now);
//            } catch (Exception e) {
//            }
//        }
        if (frame == null) {
            graph.play();
        } else {
            frame.start();
        }
    }

    // ------------------------------------------------------------------------
    protected void addNodes() throws IOException {
        Map<String, Integer> nodes = props.getNodes();
        if (nodes != null && !nodes.isEmpty()) {
            int idx = 0;
            for (String profile : nodes.keySet()) {
                int nbNodes = nodes.get(profile);
                for (int i = 0; i < nbNodes; i++) {
                    graph.addNode(makeNodeId(idx++), profile);
                }
            }
        } else {
            int nbNodes = props.getNbNodes();
            if (nbNodes > 0) { // add 'nbNodes' nodes
                for (int i = 0; i < nbNodes; i++) {
                    graph.addNode(makeNodeId(i), null);
                }
            }
        }
    }

    // ------------------------------------------------------------------------
    private String makeNodeId(int i) {
        String nb = new DecimalFormat("00000").format(i);
        return "N" + nb;
    }

    //-------------------------------------------------------------------------
    public void close() {
        if (console != null) {
            console.closeConsole();
        }
        graph.close();
    }
}

// ----------------------------------------------------------------------------
/**
 * Closes all resources if the program shuts down.
 *
 * @author launay
 */
class ShutdownThread extends Thread {

    private final leptond daemon;

    public ShutdownThread(leptond daemon) {
        this.daemon = daemon;
    }

    @Override
    public void run() {
        daemon.close();
    }
}
