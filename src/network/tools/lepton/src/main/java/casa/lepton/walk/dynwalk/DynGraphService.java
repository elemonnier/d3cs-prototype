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

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * Stub pour l'ajout et le retrait d'arc dans un graphe dynamique par RMI.
 *
 */
public interface DynGraphService extends Remote {

    /**
     * Retire un arc
     *
     * @param id identifiant de l'arc dans le fichier DGS
     * @throws RemoteException
     */
    public void removeEdge(String id) throws RemoteException;

    /**
     * Ajoute un arc qui avait été retiré par {@link #removeEdge(String)}
     *
     * @param id idnetifiant de l'arc
     * @throws RemoteException
     */
    public void addEdge(String id) throws RemoteException;

}
