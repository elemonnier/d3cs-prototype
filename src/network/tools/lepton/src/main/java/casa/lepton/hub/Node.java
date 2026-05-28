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
 * ****************************************************************************T
 * $Id$
 * ****************************************************************************/

package casa.lepton.hub;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.HashMap;

import casa.util.Logger;
import casa.lepton.hub.Proxy;
import casa.lepton.hub.Beacon;


public class Node {

    private String nodeId_ = null;
    public long lastSeen = 0;
    private InetSocketAddress baddr_ = null;  // Beaconing address
    private Map<Beacon.GossipingType,Proxy> proxies_ =
	new HashMap<Beacon.GossipingType,Proxy>();

    // ------------------------------------------------------------
    public Node(String nodeId,
		InetSocketAddress baddr) {
	nodeId_ = nodeId;
	baddr_ = baddr;
    }
    
    // --------------------------------------------------
    public String id() {
	return nodeId_;
    }

    // --------------------------------------------------
    public InetSocketAddress beaconingAddress() {
	return baddr_;
    }

    // --------------------------------------------------
    public void setBeaconingAddress(InetSocketAddress baddr) {
	baddr_ = baddr;
    }

    // --------------------------------------------------
    public InetSocketAddress gossipingAddress(Beacon.GossipingType type) {
	Proxy proxy = proxies_.get(type);
	if (proxy == null)
	    return null;
	return proxy.remoteAddress();
    }

    // ------------------------------------------------------------
    public int localPort(Beacon.GossipingType type) {
	Proxy proxy = proxies_.get(type);
	if (proxy == null)
	    return -1;
	return proxy.localPort();
    }

    // ------------------------------------------------------------
    public Proxy getProxy(Beacon.GossipingType type) {
	return proxies_.get(type);
    }
	
    // ------------------------------------------------------------
    public void setProxy(Beacon.GossipingType type, Proxy proxy) {

	Proxy formerProxy = proxies_.get(type);
	if (formerProxy != null)
	    formerProxy.clear();

	proxies_.put(type, proxy);
    }

    // ------------------------------------------------------------
    public void clear() {

	for (Proxy proxy: proxies_.values())
	    proxy.clear();
	proxies_.clear();
    }

}
