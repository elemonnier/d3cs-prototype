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
 * $Id: StreamRelay.java $
 * ****************************************************************************/

package casa.lepton.hub;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import casa.lepton.OppNet;
import casa.util.Logger;
import casa.lepton.hub.Hub;
import casa.lepton.hub.OppNetAdapter;

public class StreamRelay extends Thread {

    // public static int pipeCounter = 0;
    // public static int activePipes = 0;
    // private static long start = System.currentTimeMillis();

    // ==================================================
    private static class Lock {

	private static Object lock_;

	private synchronized static Object lock() {
	    if (lock_ == null)
		lock_ = new Object();
	    return lock_;
	}
    }
    
    
    // ==================================================
    private class StreamPipe extends Thread {

	private byte[] buffer_ = new byte[1024];
	private String sdr_;
	private String rcv_;
	private Socket inSocket_;
	private Socket outSocket_;
	private StreamRelay relay_;
	public String peerId = null;

	boolean running = false;

	public StreamPipe(String sdr,
			  String rcv,
			  Socket in,
			  Socket out,
			  StreamRelay relay)
	throws Exception {

	    sdr_ = sdr;
	    rcv_ = rcv;
	    inSocket_ = in;
	    outSocket_ = out;
	    relay_ = relay;
	}
	
	// --------------------------------------------------
	private void runBytewise(InputStream in,
				 OutputStream out)
	    throws Exception {

	    int len = in.read(buffer_);
	    while (len != -1) {
		relay_.checkConnectivity();

		// synchronized(Lock.lock()) {
		//     sleep(90);
		// }
		// int nbNeigh = oppNet_.nbNeighbors(sdr_, null, null);
		// long wait = nbNeigh * 520;
		// Logger.log("defer",
		//  	       "[" + nbNeigh + "/" + wait + "]> "
		//  	       + this);
		// sleep(wait);

		Logger.log("relay",
		 	       "[" + len + "]> "
		 	       + this);
		EdgeTransferHighlighter.highlight(oppNet_, sdr_, rcv_);
		out.write(buffer_, 0, len);
		len = in.read(buffer_);
	    }
	}
	
	// --------------------------------------------------
	public void run() {

	    InputStream in = null;
	    OutputStream out = null;
	    try {
		in = inSocket_.getInputStream();
		out = outSocket_.getOutputStream();
	    }
	    catch(Exception e) {
		Logger.log("relay", "error: failed to start " + this);
		return;
	    }
	    
	    running = true;
		
	    try {
		runBytewise(in, out);
	    }
	    catch (Exception e) {
	    }

	    this.close();
	}

	// --------------------------------------------------
	public void close() {

	    running = false;
	    
	    if (relay_ != null) {
		// activePipes--;
		// long now = System.currentTimeMillis() - start;
		// System.err.println(now + " " + activePipes);
		relay_.close();
		inSocket_ = null;
		outSocket_ = null;
		relay_ = null;
		// System.err.println("Terminate " + this.getName()
		// 		   + " (active=" + activePipes + ")");
	    }
	}
	
	// --------------------------------------------------
	public String toString() {

	    return "Pipe("
		+ StreamRelay.toString((InetSocketAddress)inSocket_.getRemoteSocketAddress())
		+ " => "
		+ StreamRelay.toString((InetSocketAddress)outSocket_.getRemoteSocketAddress())
		+ ")";
	}
	
    }
    // ==================================================

    private String callerId_ = null;
    private String calledId_ = null;
    private Socket callerSock_;
    private Socket calledSock_;
    private InetSocketAddress calledAddr_ = null;
    private StreamPipe pipe1_;
    private StreamPipe pipe2_;
    private boolean isClosed_ = false;
    private OppNet oppNet_;
    private OppNetAdapter adapter_ = null;
    private EdgeSessionStatus edgeSessionStatus_;
    private String connectivityType = null;

    // ------------------------------------------------------------
    public StreamRelay(String calledId, InetSocketAddress calledAddr,
		       Socket callerSock, OppNet oppNet, EdgeSessionStatus sessionStatus)
	throws Exception {

	calledId_ = calledId;
	callerSock_ = callerSock;
	calledAddr_ = calledAddr;
	oppNet_ = oppNet;
        edgeSessionStatus_ = sessionStatus;
	adapter_ = Hub.getAdapter();
    }

    // ------------------------------------------------------------
    public void run() {

	// Logger.log("relay", "opening " + this);

	try {
	    OppNetAdapter.StreamHeader header =
		adapter_.getStreamHeader(callerSock_.getInputStream());
	    callerId_ = header.getSource();
	    Logger.log("relay", "< callerId=" + callerId_);

	    // 'Caller' is trying to connect to 'called'. Let us check
	    // if they should be allowed to do so
	    boolean connected = oppNet_.areNeighbors(callerId_, calledId_, connectivityType, null);
	    if (connected) {
		calledSock_ = new Socket(calledAddr_.getAddress(),
					   calledAddr_.getPort());

		Logger.log("relay", "opened " + this);

		edgeSessionStatus_.setEdgeStatus(callerId_, calledId_, connectivityType, "CONNECTED");

		// Sending to called what has been read from caller so
		// far
		calledSock_.getOutputStream().write(header.getBytes());

		// Starting bi-directional piping between caller and
		// called
		pipe1_ = new StreamPipe(callerId_, calledId_,
					callerSock_, calledSock_, this);
		pipe2_ = new StreamPipe(calledId_, callerId_,
					calledSock_, callerSock_, this);

		pipe1_.start();
		pipe2_.start();
	    }
	    else {
		// Nope. Connection is not allowed. Let us close
		// caller socket.
		try { callerSock_.close(); } catch(Exception e) {}
	    }
	}
	catch (Exception e) {
	    close();
	}
    }
    
    // ------------------------------------------------------------
    public synchronized void close() {

	if (isClosed_)
	    return;

	isClosed_ = true;
	
	Logger.log("relay", "closing " + this);
	
	try { callerSock_.close(); } catch(Exception e) {}
	try { calledSock_.close(); } catch(Exception e) {}

	// System.err.println("DISCONNECTED: " + pipe1_.peerId
	// 		   + " " + pipe2_.peerId);
	// env_.setConnectionStatus(pipe1_.peerId, pipe2_.peerId,
	// false);
	// FG: 
	// notifyConnectionStatus(false);

    	callerSock_ = null;
	pipe1_ = null;
	calledSock_ = null;
	pipe2_ = null;

        edgeSessionStatus_.setEdgeStatus(callerId_, calledId_, connectivityType, "DISCONNECTED");
}

    // ------------------------------------------------------------
    public synchronized boolean checkConnectivity() {

	boolean connected = oppNet_.areNeighbors(callerId_, calledId_, null, null);
	if (! connected)
	    close();

	return connected;
    }

    // ------------------------------------------------------------
    public String toString() {

	return "StreamRelay(" + callerId_ + " <=> " + calledId_ + ")";

	// return "StreamRelay("
	//     + (callerId_==null?"":callerId_ + "/")
	//     + toString((InetSocketAddress)callerSock_.getRemoteSocketAddress())
	//     + " <=> "
	//     + (calledId_==null?"":calledId_ + "/")
	//     + (calledSock_==null?"":toString((InetSocketAddress)calledSock_.getRemoteSocketAddress()))
	//     + ")";
    }

    // --------------------------------------------------
    protected static String toString(InetSocketAddress saddr) {
	
	if (saddr == null)
	    return "null";

	InetAddress addr = saddr.getAddress();
	int port = saddr.getPort();

	return (addr==null?"null:":addr.getHostAddress()) + ":" + port;
    }
}
