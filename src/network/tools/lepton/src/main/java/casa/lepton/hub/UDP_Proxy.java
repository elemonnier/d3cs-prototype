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
import casa.lepton.OppNet;
import casa.lepton.hub.UDP_Channel;
import casa.lepton.hub.OppNetAdapter;


public class UDP_Proxy
    extends Proxy implements Processor<DatagramPacket> {

    private UDP_Channel channel_ = null;
    private InetSocketAddress remoteAddr_  = null;  // Remote address for which this is a proxy
    private int localPort_ = 0;
    private OppNet oppNet_ = null;
    private OppNetAdapter adapter_ = null;
    private String nodeId_ = null;
    
    // ------------------------------------------------------------
    public UDP_Proxy(String nodeId,
		     OppNet oppNet,
		     InetSocketAddress addr) {

	nodeId_ = nodeId;
	oppNet_ = oppNet;
	remoteAddr_ = addr;

	adapter_ = Hub.getAdapter();

	try {
	    remoteAddr_ = addr;
	    InetSocketAddress any_addr = new InetSocketAddress("::", 0);
	    channel_ = new UDP_Channel(any_addr, this);
	    localPort_ = channel_.localPort();
	    
	    Logger.log("hub", "creating UDP_Proxy on port "
		       + localPort_
		       + " for peer " + addr);
	    channel_.setProcessor(this);
	    channel_.open();
	}
	catch (Exception e) {
	    System.out.println(e);
	    e.printStackTrace();
	}
     }
    
    // --------------------------------------------------
    public InetSocketAddress remoteAddress() {
	return remoteAddr_;
    }

    // --------------------------------------------------
    public InetSocketAddress localAddress() {
	return channel_.localAddress();
    }

    // --------------------------------------------------
    public int localPort() {
	
	return localPort_;
    }

    // --------------------------------------------------
    public void process(DatagramPacket packet) {

	try {
	    String source = adapter_.getSource(packet);
	    Logger.log("hub", "<< src='" + source + "'");

	    // Let us make sure node 'source' is allowed to access
	    // node 'nodeId_'
	    if (oppNet_.areNeighbors(source, nodeId_, null, null)) {
		    // Forwarding datagram packet to peer
		    EdgeTransferHighlighter.highlight(oppNet_, source, nodeId_);
		    packet.setSocketAddress(remoteAddr_);
		    channel_.send(packet);
		}
	}
	catch (Exception e) {
	    Logger.log("hub", "UDP_Proxy failed to relay packet to " + remoteAddr_);
	}
    }

     // ------------------------------------------------------------
    public void clear() {
	
	Logger.log("hub", "clearing UDP_Proxy listening on " + localPort_
		   + " for peer " + remoteAddr_);
	
	try {
	    channel_.close();
	}
	catch(Exception e) {
	}
    }

}
