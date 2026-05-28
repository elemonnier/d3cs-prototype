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

import casa.lepton.OppEdge;
import java.util.Collection;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.net.InetSocketAddress;
import java.net.DatagramPacket;
import java.lang.reflect.Constructor;

import java.net.NetworkInterface;
import java.net.InetAddress;
import java.net.Inet4Address;
import java.util.Enumeration;

import casa.util.Logger;
import casa.util.Processor;
import casa.lepton.OppNet;
import static casa.lepton.OppNet.EDGE_ADDED;
import casa.lepton.conf.OppNetProperties;

public class Hub
        extends Thread
        implements Processor<DatagramPacket> {

    private final OppNet oppNet_;
    public long latency = 60;
    public long period = 10;

    private Map<String, Node> nodes_
            = new HashMap<String, Node>();

    private InetAddress localAddr_ = null;

    private UDP_Channel channel_;
    private static OppNetAdapter adapter_ = null;

    private EdgeSessionStatus sessionStatus_;

    // -------------------------------------------------------------------
    public Hub(OppNet oppNet, OppNetProperties props)
            throws Exception {

        this.nodes_ = new HashMap<>();

        adapter_ = props.getOppNetAdapter();

        Logger.enable(null, true, "hub");
        Logger.log("adapter", adapter_.getClass().getName());

        localAddr_ = getInet4Address();

        oppNet_ = oppNet;
        sessionStatus_ = new EdgeSessionStatus(oppNet);
        this.latency = props.getHubLatency();
        this.period = props.getHubPeriod();
        int port = props.getHubPort();

        // Open a UDP socket on which beacons should be received, and
        // set this Hub as a processor for these beacons
        channel_ = new UDP_Channel(new InetSocketAddress("::", port), this);

        channel_.open();
    }

    // ------------------------------------------------------------
    private static void setAdapter(String className)
            throws Exception {

        Class class_ = Class.forName(className);
        Constructor constructor
                = class_.getConstructor(new Class[]{});
        adapter_ = (OppNetAdapter) constructor.newInstance();
    }

    // ------------------------------------------------------------
    public static OppNetAdapter getAdapter() {
        return adapter_;
    }

    // ============================================================
    // Interface management
    // ============================================================
    public static InetAddress getInet4Address() {

        try {
            for (Enumeration e
                    = NetworkInterface.getNetworkInterfaces(); e.hasMoreElements();) {
                NetworkInterface iface = (NetworkInterface) e.nextElement();
                System.out.println("\nName : " + iface.getDisplayName()
                        + (iface.isUp() ? " (UP)" : " (DOWN)")
                        + (iface.supportsMulticast() ? " (MCAST)" : ""));
                if (iface.isUp()) {
                    for (Enumeration<InetAddress> a
                            = iface.getInetAddresses(); a.hasMoreElements();) {
                        InetAddress add = a.nextElement();
                        if ((add instanceof Inet4Address) // IPv4 address
                                && (!add.isAnyLocalAddress()) // Not wildcard
                                && (!add.isLoopbackAddress()) // Not loopback
                                && (!add.isLinkLocalAddress())) // Not link local
                        {
                            return add;
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.out.println(e);
        }

        return null;
    }

    // ============================================================
    // MANAGEMENT OF CLIENT NODES
    // ============================================================
    private void purgeOldNodes() {

        // Logger.log("hub", "purging old nodes (if any...)");
        long now = System.currentTimeMillis();

        // Let us remove nodes we haven't heard about for a long time
        synchronized (oppNet_) {
            Set<String> oldNodes = new HashSet<String>();
            for (String id : nodes_.keySet()) {
                Node node = nodes_.get(id);
                long elapsed = (now - node.lastSeen) / 1000;
                if (elapsed > latency) {
                    oldNodes.add(id);
                    Logger.log("hub", " purge " + id
                            + " (elapsed=" + elapsed
                            + " sec)");
                }
            }
            for (String id : oldNodes) {
                removeNode(id);
            }
        }
    }

    // ------------------------------------------------------------
    private void removeNode(String id) {

        Node node = nodes_.get(id);
        if (node != null) {
            node.clear();
            nodes_.remove(id);
        }
        oppNet_.deleteNode(id);
    }

    // ------------------------------------------------------------
    public void run() {

        try {
            while (true) {

                sleep(period * 1000);
                purgeOldNodes();
            }
        } catch (Exception e) {
            System.out.println("Hub.run(): " + e);
            e.printStackTrace();
        }
    }

    // ------------------------------------------------------------
    public void notifyEdgeListeners(OppEdge edge, String command) {
        if (command.equals(EDGE_ADDED)) {
            sessionStatus_.edgeAdded(edge);
        }
    }
    // ============================================================
    // Implementation of the Processor<DatagramPacket> interface
    // ============================================================

    // ------------------------------------------------------------
    private void processHelloBeacon(Beacon beacon, Node node,
            InetAddress srcAddr)
            throws Exception {

        // Processing a 'hello' beacon we've received from a node
        // whose address is 'srcAddr':
        //
        // for each known gossiping type, if a gossiping address
        // is specified in the beacon:
        //
        //   (a) the address is processed: if the beacon only
        //   specifies the port number used by the sender, fill in the
        //   address based on the source address of the packet we have
        //   received
        //
        //   (b) a proxy is created for the gossiping type and
        //   address, unless there already is one
        //
        //   (c) the beacon is modified, so the gossiping address is
        //   now that of the local proxy
        // Let us consider each known gossiping type
        for (Beacon.GossipingType gtype : Beacon.GossipingType.values()) {

            // (a) If a gossiping address is specified in the beacon
            // for that gossiping type, let us try to create a proxy
            // for traffic sent to that address
            InetSocketAddress gaddr = beacon.getGossipingAddress(gtype);
            if (gaddr != null) {
                int gport = gaddr.getPort();
                // If the gossiping address does not specify the host
                // (i.e., only the gossiping port is specified), let
                // us use the source address of the UDP packet
                boolean portOnly
                        = gaddr.getAddress().isAnyLocalAddress();
                if (portOnly) {
                    gaddr = new InetSocketAddress(srcAddr, gport);
                }

                // (b) Let us create a proxy for that gossiping type
                // and address, unless there is already one
                Proxy proxy = node.getProxy(gtype);
                if ((proxy == null)
                        || (!gaddr.equals(proxy.remoteAddress()))) {
                    proxy = createProxy(node.id(), gtype, gaddr);
                    if (proxy != null) {
                        node.setProxy(gtype, proxy);
                    }
                }

                // (c) Let us modify the beacon, so the gossiping
                // address it contains is that of the local proxy
                int localPort = proxy.localAddress().getPort();
                // If the received beacon only specified the gossiping
                // port number of the sender, let us modify the beacon
                // so that it only specifies the port number of the
                // proxy
                if (portOnly) {
                    gaddr = new InetSocketAddress((InetAddress) null,
                            localPort);
                } else // Otherwise let us modify the so it also
                // specifies the address of the hub
                {
                    gaddr = new InetSocketAddress(localAddr_,
                            localPort);
                }
                beacon.setGossipingAddress(gtype, gaddr);
            }
        }
    }

    // ------------------------------------------------------------
    public void process(DatagramPacket packet)
            throws Exception {

        // Processing a beacon: the UDP packet we've received from a
        // node is theoretically a beacon. This packet shall be
        // processed as follows:
        //
        // (1) the packet is decoded as a beacon
        //
        // (2) if the sender of the beacon is not known yet, it is
        // registered as a new node
        //
        // (3) if the beacon is a 'hello' beacon, it is processed as such
        //
        // (4) the beacon is re-encoded as a UDP packet
        //
        // (5) the beacon is forwarded to a single receiver if
        // requested by the sender (5.1) or to all peers of the sender
        // (5.2)
        // Logger.log("hub", "< ["
        //  	   + packet.getLength() + "] " 
        //  	   + packet.getSocketAddress());
        try {
            // (1) Decoding the beacon
            Beacon beacon = adapter_.getBeacon(packet);
	    InetSocketAddress baddr = (InetSocketAddress) packet.getSocketAddress();
            Logger.log("beacon", "< " + beacon);
            String sdr = beacon.getSource();
            String rcv = beacon.getDestination();
            Beacon.BeaconType btype = beacon.getBeaconType();

            // Check if the sender is already known
            boolean dup = nodes_.containsKey(sdr);
            boolean hello = (btype == Beacon.BeaconType.HELLO);

            Logger.log("hub", "< [beacon] sdr=" + sdr
                    + (rcv == null ? "" : ",rcv=" + rcv)
                    + (hello ? " (hello)" : " (bye)")
                    + (dup ? " [dup]" : ""));

            synchronized (oppNet_) {

                // (2) If the sender is not known yet, register it as a new
                // node
                Node node;
                if (!dup) {
                    node = new Node(sdr, baddr);
                    nodes_.put(sdr, node);
                    oppNet_.addNode(sdr, null);
                } else {
                    node = nodes_.get(sdr);
		    // Record the sender's beaconing address again
		    // (just in case it has changed)
		    if (! baddr.equals(node.beaconingAddress())) {
			    Logger.log("hub", "baddr changed for sdr=" + sdr);
			    node.setBeaconingAddress(baddr);
			}
                }

                // Record that this is the last time we've received a
                // beacon from that node
                node.lastSeen = System.currentTimeMillis();

                // (3) If this is a 'hello' beacon, process it accordingly
                if (hello) {
                    processHelloBeacon(beacon, node, packet.getAddress());
                }

                Logger.log("beacon", "> " + beacon);

                // (4) Re-encode the beacon as a packet
                int length = beacon.encode(packet.getData(),
                        packet.getOffset());
                packet.setLength(length);

                // (5) Forward the beacon
                if (rcv != null) {
                    // (5.1) Forwarding to one receiver only (as requested
                    // by the sender)
                    if (oppNet_.areNeighbors(sdr, rcv, null, null)) {
                        Logger.log("hub", "  > sdr=" + sdr
                                + ",rcv=" + rcv);
                        send(packet, rcv);
                    }
                } else {
                    // (5.2) Forwarding to all peers (i.e., neighbors)
                    // of the sender
                    Collection<String> peers = oppNet_.getNeighbors(sdr, null, null);
                    Set<String> targets = new HashSet<String>();
                    for (String id : peers) {
                        targets.add(id);
                    }
                    if (!targets.isEmpty()) {
                        Logger.log("hub", "  > sdr=" + sdr
                                + ",rcv="
                                + toString(peers, ","));
                        for (String id : targets) {
                            send(packet, id);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Logger.log("hub", "Beacon processing failed.");
            // e.printStackTrace();
        }
    }

    // ------------------------------------------------------------
    private Proxy createProxy(String nodeId,
            Beacon.GossipingType type,
            InetSocketAddress addr) {

        Logger.log("hub", "Creating a proxy for " + addr);
        Proxy proxy = null;
        switch (type) {
            case TCP:
                proxy = new TCP_Proxy(nodeId, oppNet_, sessionStatus_, addr);
                break;
            case UDP:
                proxy = new UDP_Proxy(nodeId, oppNet_, addr);
                break;
        }
        return proxy;
    }

    // ------------------------------------------------------------
    private static String toString(Collection<String> values,
            String separator) {

        if (values == null) {
            return "";
        }

        String result = "";

        boolean firstItem = true;
        for (String key : values) {
            if (firstItem) {
                result = key;
                firstItem = false;
            } else {
                result += separator + key;
            }
        }

        return result;
    }

    // ------------------------------------------------------------
    private void send(DatagramPacket packet, String rcv) {

        Node node = nodes_.get(rcv);
        if (node == null) {
            Logger.log("hub", "warning: rcv=" + rcv + " unknown");
            return;
        }
        InetSocketAddress addr = node.beaconingAddress();
        packet.setSocketAddress(addr);
        try {
            channel_.send(packet);
        } catch (Exception e) {
            Logger.log("hub", "failed to send packet to rcv=" + rcv
                    + " " + addr);
        }
    }

}
