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
 * $Id: UDP_Channel.java $
 * ****************************************************************************/

package casa.lepton.hub;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.DatagramSocket;
import java.net.DatagramPacket;

import casa.util.Logger;
import casa.util.Processor;

public class UDP_Channel 
    extends Thread {

    public static final int MAX_BUFFER_SIZE = 65507;

    private DatagramSocket socket_ = null;

    private InetSocketAddress localSocketAddr_  = null;
    
    private boolean isOpen_ = false;

    private Processor<DatagramPacket> processor_ = null;
    
    // ============================================================
    public UDP_Channel(InetSocketAddress localSocketAddr,
		       Processor<DatagramPacket> proc) throws IOException {

	processor_ = proc;

	try {	
	    socket_ = new DatagramSocket(localSocketAddr);
	    localSocketAddr_  = (InetSocketAddress)socket_.getLocalSocketAddress();
	
	    Logger.log("udp_chan", "create " + this);
	} catch (IOException e) {
	    Logger.log("udp_chan", "create " + localSocketAddr + " failed");
	    throw e;
	}
    }

    // ------------------------------------------------------------
    public void setProcessor(Processor<DatagramPacket> proc) {
	processor_ = proc;
    }

    // ------------------------------------------------------------
    public InetSocketAddress localAddress() {

	return (InetSocketAddress)socket_.getLocalSocketAddress();
    }

    // ------------------------------------------------------------
    public int localPort() {

	return socket_.getLocalPort();
    }
    
    // ------------------------------------------------------------
    public void run() {

	isOpen_ = true;

	try {
	    while (true) {
		DatagramPacket packet = receive();
		if (processor_ != null)
		    processor_.process(packet);
	    }
	}
	catch(Exception e) {
	    if (isOpen_)
		Logger.log("udp_chan", "rcv_failure");
	}

	if (isOpen_)
	    close();
	
	isOpen_ = false;
	Logger.log("udp_chan", "terminate");
    }

    // ------------------------------------------------------------
    public DatagramPacket receive() throws IOException {
	
	DatagramPacket inPacket =
	    new DatagramPacket(new byte[MAX_BUFFER_SIZE],
			       MAX_BUFFER_SIZE);
	
	socket_.receive(inPacket);

	Logger.log("udp_chan", "< ["
	 	   + inPacket.getLength() + "] " 
	 	   + inPacket.getSocketAddress());
	
	return inPacket;
    }

    // ------------------------------------------------------------
    public void send(DatagramPacket packet)
	throws IOException {
	
	try {
	    socket_.send(packet);
	    
	    Logger.log("udp_chan", "> ["
	     	       + packet.getLength() + "] " 
	     	       + packet.getSocketAddress());
	    
	} catch (IOException e) {
	    System.out.println("UDP_Channel: could not send packet");
	    throw e;
	}
    }
	
    // ------------------------------------------------------------
    public void open() {

	if (isOpen_)
	    return;
	
	Logger.log("udp_chan", "open "
		   + this);
	
	start();
    }
    
    // ------------------------------------------------------------
    public void close() {

	if (! isOpen_)
	    return;
	
	Logger.log("udp_chan", "close " + this);

	isOpen_ = false;
	
	try {
	    this.interrupt();
	    socket_.close();
	}
	catch (Exception e) {}
    }

    // ------------------------------------------------------------
    public boolean isOpen() {

	return isOpen_;
    }

    // ------------------------------------------------------------
    public String toString() {

	return "UDP_Channel(local="
	    + localSocketAddr_
	    + ")";
    }
}
