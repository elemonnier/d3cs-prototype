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

import java.util.Set;
import java.util.HashSet;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.DatagramPacket;

import casa.util.Logger;
import casa.util.Processor;
import casa.lepton.hub.UDP_Channel;


public abstract class Proxy {

    // --------------------------------------------------
    public abstract InetSocketAddress remoteAddress();

    // --------------------------------------------------
    public abstract InetSocketAddress localAddress();

    // --------------------------------------------------
    public abstract int localPort();

    // ------------------------------------------------------------
    public abstract void clear();

}
