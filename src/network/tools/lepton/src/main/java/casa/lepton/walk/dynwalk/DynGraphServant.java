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

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

/**
 * 
 */
@SuppressWarnings("serial")
public class DynGraphServant extends UnicastRemoteObject implements DynGraphService {

    private DynGraphWalk walk;

    protected DynGraphServant(DynGraphWalk walk) throws RemoteException {
        super();
        this.walk = walk;
    }

    /* (non-Javadoc)
	 * @see casa.mobsim.walk.DynGraphService#removeEdge()
     */
    @Override
    public void removeEdge(String id) throws RemoteException {
        walk.removeEdge(id);
    }

    /* (non-Javadoc)
	 * @see casa.mobsim.walk.DynGraphService#addEdge()
     */
    @Override
    public void addEdge(String id) throws RemoteException {
        walk.addEdge(id);
    }

}
