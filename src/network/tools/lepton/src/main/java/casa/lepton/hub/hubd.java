/* *****************************************************************************
 * Copyright (c) 2005-2010 VALORIA Laboratory, 
 * Universite Europeenne de Bretagne, Universite de Bretagne-Sud, France
 * <http://www-valoria.univ-ubs/CASA/DoDWAN>
 *
 * This file is part of DoDWAN.
 * 
 * DoDWAN is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software 
 * Foundation, either version 3 of the License, or any later
 * version.
 * 
 * DoDWAN is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DoDWAN.  If not, see <http://www.gnu.org/licenses/>.
 * ****************************************************************************
 * $Id$
 * ****************************************************************************/
package casa.lepton.hub;

import casa.lepton.OppNetFullyConnected;
import casa.lepton.OppNet;
import casa.lepton.conf.OppNetProperties;

public class hubd {

    // ------------------------------------------------------------------------
    private static void usage() {

        System.out.println("\nRun the LEPTON hub in a fully connected mode");
        System.out.println("\nArguments: [conf=confFile]* [key=value]*");
        System.out.println("    conf=confFile  configuration file defining some properties");
        System.out.println("    key=value      a configuration property\n");
        System.out.println("The configuration files and properties passed as arguments overwrite the default configuration\n");

        System.exit(1);

    }

    // ------------------------------------------------------------
    public static void main(String[] args) throws Exception {

        if (args.length > 0 && args[0].equals("-h")) {
            usage();
        }

        OppNetProperties props = new OppNetProperties(args);

        if (props.getHubPeriod() > 0) {
            OppNet oppNet = new OppNetFullyConnected();
            Hub hub = new Hub(oppNet, props);
            hub.start();
        }
    }
}
