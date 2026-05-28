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

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;

/**
 * Client RMI pour communiquer avec le simulateur Mobsim et ajouter ou retirer
 * dynamiquement des arcs dans le graphe de mobilité.
 *
 */
public class DynGraphClient {

    DynGraphService dynGraphService;

    /**
     * Client qui communique avec le serveur RMI d'ajout ou de retrait dynamique
     * d'arcs de Mobsim
     *
     * @param url URL du serveur RMI (voir {@link DynGraphWalker#startServer()})
     */
    public DynGraphClient(String url) {
        try {
            dynGraphService = (DynGraphService) Naming.lookup(url);
        } catch (MalformedURLException | RemoteException | NotBoundException e) {
            System.out.println("DynGraphService not founded");
            e.printStackTrace();
        }
    }

    /**
     * Retire un arc
     *
     * @param id identifiant de l'arc dans le fichier DGS
     * @throws RemoteException
     */
    public void removeEdge(String id) throws RemoteException {
        dynGraphService.removeEdge(id);
    }

    /**
     * Ajoute un arc
     *
     * @param id identifiant de l'arc qui avait été retiré par
     * {@link #removeEdge(String)}
     * @throws RemoteException
     */
    public void addEdge(String id) throws RemoteException {
        dynGraphService.addEdge(id);
    }

}
