
package casa.lepton.hub;

import java.io.InputStream;
import java.net.DatagramPacket;

import casa.lepton.hub.Beacon;

public interface OppNetAdapter {

    // ============================================================
    public class StreamHeader {
	
	private String source_;
	private byte[] buffer_ = null;
	
	// --------------------------------------------------------
	public StreamHeader(String source, byte[] buffer) {
	    
	    source_ = source;
	    buffer_ = buffer;
	}
	
	// --------------------------------------------------------
	// Return the identity of the source of that stream (this
	// source should only be known once read(...) has been
	// executed)
	public String getSource() {
	    return source_;
	}
	
	// --------------------------------------------------------
	// Return a buffer containing the bytes that constitute this
	// header
	public byte[] getBytes() {
	    return buffer_;
	}
    }
    // ============================================================

    
    // ------------------------------------------------------------
    // Decode and return a beacon based on data available in the
    // buffer
    public Beacon getBeacon(DatagramPacket packet)
	throws Exception;

    // ------------------------------------------------------------
    // Decode the sequence of bytes received from an input stream,
    // until the identity of the source of this stream has been
    // identified, then return a StreamHeader that contains the source
    // id, and the bytes that have been read so far
    public StreamHeader getStreamHeader(InputStream in)
	throws Exception ;

    // ------------------------------------------------------------
    // Decode the packet and return the identity of its source
    public String getSource(DatagramPacket packet)
	throws Exception ;
    
}
