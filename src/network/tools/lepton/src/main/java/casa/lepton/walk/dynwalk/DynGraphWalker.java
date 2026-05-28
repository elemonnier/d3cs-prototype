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
package casa.lepton.walk.dynwalk;

import casa.lepton.walk.Step;
import casa.lepton.walk.GraphWalker;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.RemoteException;

/**
 * Un GraphWalker dont les arcs du graphe sous-jacent peuvent être supprimés ou
 * ajoutés dynamiquement par un autre processus via un serveur RMI.
 * 
 */
public class DynGraphWalker extends GraphWalker {

    static public final int PORT = 1099; // port RMI par défaut
    static public final String HOST = "cetyounix";
    public static final String NAME = "mobsim";
    public static final String RMI_URL = "rmi://" + HOST + ":" + PORT + "/" + NAME;

    // ------------------------------------------------------------
    public DynGraphWalker(DynGraphWalk walk, long time, String pauseType) {

        super(walk, time, pauseType);
        try {
            startServer();
        } catch (RemoteException | MalformedURLException e) {
            System.out.println("The launching of the RMI server failed");
        }
    }

    // ------------------------------------------------------------
    public Step nextStep(long time) {

        departureNode_ = arrivalNode_;
        if ((path_ == null) || path_.isEmpty()
                || !departureNode_.hasEdgeBetween(path_.get(0))) {// FR: cas où le graphe aurait changé (suppression d'un arc)
            do {
                computeNextPath(time);
            } while (path_ == null);
            // First node in path should be departureNode_
            if (!path_.isEmpty()) {
                path_.remove(0);
            }
        }

        arrivalNode_ = path_.get(0);
        path_.remove(0);

        boolean endOfPath = path_.isEmpty();
        step_ = getStep(time, departureNode_, arrivalNode_, endOfPath);

//        System.out.println("next step=" + step_);
        return step_;
    }

    /**
     * Lance un RMI registry Créé et enregistre le stub RMI pour les méthodes
     * d'ajout et de suppression d'arcs
     *
     * @throws RemoteException
     * @throws MalformedURLException
     */
    private void startServer() throws RemoteException, MalformedURLException {
        try {
            java.rmi.registry.LocateRegistry.createRegistry(PORT);
        } catch (Exception ignore) {
            System.out.println("rmiregistry already started");
        }
        if (System.getSecurityManager() == null) {
            System.setSecurityManager(new SecurityManager()); // contrôle des sockets, ports et fichiers
            System.out.println("security manager started");
        } else {
            System.out.println("security manager already started");
        }
        DynGraphService servant = new DynGraphServant((DynGraphWalk) walk_);
        System.out.println("remote object created");
        Naming.rebind(RMI_URL, servant);
        System.out.println("stub registered");
        System.out.println("RMI server started");
    }
}
