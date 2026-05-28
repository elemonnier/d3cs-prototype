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

import java.lang.Runnable;
import java.util.Set;
import java.util.HashSet;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

import casa.util.Logger;
import casa.lepton.OppNet;
import casa.lepton.hub.Proxy;
import casa.lepton.hub.StreamRelay;


public class TCP_Proxy
    extends Proxy implements Runnable  {

    private ServerSocket server_    = null;
    private InetSocketAddress remoteAddr_ = null;  // Remote address for which this is a proxy
    private int localPort_ = 0;
    private Set<StreamRelay> relays_ = new HashSet<StreamRelay>();
    private OppNet oppNet_ = null;
    private EdgeSessionStatus sessionStatus_;
    private String nodeId_ = null;
    
    // ------------------------------------------------------------
    public TCP_Proxy(String nodeId,
		     OppNet oppNet,
                     EdgeSessionStatus sessionStatus,
		     InetSocketAddress addr) {
	nodeId_ = nodeId;
	oppNet_ = oppNet;
        sessionStatus_ = sessionStatus;
	remoteAddr_ = addr;

	try {
	    remoteAddr_ = addr;
	    server_ = new ServerSocket(0);
	    localPort_ = server_.getLocalPort();
	    
	    Logger.log("hub", "creating TCP proxy socket on port "
		       + server_.getLocalPort()
		       + " for peer " + remoteAddr_);
	}
	catch (Exception e) {
	    System.out.println(e);
	    e.printStackTrace();
	}

	Thread thread = new Thread(this);
	thread.setName("TCP_Proxy_" + remoteAddr_);
	thread.start();
     }
    
    // --------------------------------------------------
    public InetSocketAddress remoteAddress() {
	return remoteAddr_;
    }

    // --------------------------------------------------
    public InetSocketAddress localAddress() {
	return (InetSocketAddress)server_.getLocalSocketAddress();
    }

    // --------------------------------------------------
    public int localPort() {
	
	return localPort_;
    }

    // --------------------------------------------------
    public void run() {
	
	// System.err.println("Begin " + this.getName());
	
	if (server_ == null)
	    return;
	
	while(! server_.isClosed()) {
	    // Logger.log("hub", "waiting for peer on port "
	    // 	   + server_.getLocalPort());
	    try {
		Socket inSocket = server_.accept();
		
		Logger.log("hub", "cx accepted from "
			   +  StreamRelay.toString((InetSocketAddress)inSocket.getRemoteSocketAddress())
			   + ", connecting to "
			   +  remoteAddr_);
		StreamRelay relay = new StreamRelay(nodeId_, remoteAddr_,
						    inSocket, oppNet_, sessionStatus_);
		relays_.add(relay);
		relay.start();
	    }
	    catch (Exception e) {
		// System.out.println(e);
		// e.printStackTrace();
	    }
	}
	Logger.log("hub", "TCP_Proxy on local port "
		   + localPort_
		   + " terminated");
	
	// System.err.println("Terminate " + this.getName());
    }
    
    // ------------------------------------------------------------
    public void clear() {
	
	if (server_ == null)
	    return;
	
	Logger.log("hub", "clearing TCP_Proxy listening on " + localPort()
		   + " for peer " + remoteAddr_);
	
	try {
	    server_.close();
	}
	catch(Exception e) {
	}
	
	for (StreamRelay relay: relays_) 
	    relay.close();
	relays_.clear();
    }

}
