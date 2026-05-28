
package casa.lepton.hub;

import java.io.InputStream;
import java.net.InetSocketAddress;

public interface Beacon {

    // Possible types for beacons: a HELLO beacon is used by a host to
    // announce its presence in the network, a BYE beacon is used to
    // announce that a host a leaving the network. (Most DTN systems
    // only use HELLO beacons.)
    public enum BeaconType { HELLO, BYE }

    // Possible types for the gossiping ports that may be specified in
    // a beacon.
    public enum GossipingType { TCP, UDP }
    
    // ------------------------------------------------------------
    // Return the type of the beacon
    public BeaconType getBeaconType();

    // ------------------------------------------------------------
    // Return the source of the beacon
    public String getSource();

    // ------------------------------------------------------------
    // Return the destination of the beacon if specified, otherwise
    // return null
    public String getDestination();

    // ------------------------------------------------------------
    // Return the address specified for the specified gossiping
    // type. Return null if there is none.
    //
    // If the beacon only specifies a port number for the gossiping
    // type (i.e., no host address is specified), then this method
    // should return an InetSocketAddress whose address (host) field
    // is a wildcard address.
    public InetSocketAddress getGossipingAddress(GossipingType type);

    // ------------------------------------------------------------
    // Set the address for the specified gossiping port.
    //
    // If the address (host) field in addr is a wildcard address (for
    // which method InetAddress.isAnyLocalAddress() returns true),
    // then only the port number specified in addr is significant.
    public void setGossipingAddress(GossipingType type,
				    InetSocketAddress addr)
	throws Exception;

    // ------------------------------------------------------------
    // Return 'true' if the beacon contains a gossiping address for
    // the specified gossiping type; return 'false' otherwise
    public boolean hasGossipingType(GossipingType type);

    // ------------------------------------------------------------
    // Decode the beacon contained in buffer
    public void decode(byte[] buffer, int offset, int length)
	throws Exception;

    // ------------------------------------------------------------
    // Encode this beacon to buffer, and return the number of bytes
    // used with this encoding
    public int encode(byte[] buffer, int offset)
	throws Exception;
}
