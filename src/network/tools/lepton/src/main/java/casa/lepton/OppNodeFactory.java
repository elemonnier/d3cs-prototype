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
package casa.lepton;

import casa.lepton.conf.NodeLabels;
import casa.lepton.conf.OppNodeProfiles;
import casa.lepton.conf.OppNodeProperties;
import casa.lepton.walk.Walk;
import casa.lepton.walk.Walker;
import casa.util.geom.CoordCar;
import java.util.Objects;
import org.graphstream.graph.Graph;
import org.graphstream.graph.NodeFactory;

/**
 * Class used to dynamically create {@link OppNode} instances. The
 * {@link #newInstance(String, Graph)} method is called by the
 * {@link Graph#addNode(String)} method.
 *
 * Setters ({@link #setProfile(String)}, {@link #setCoord(CoordCar)}) allow to
 * set the nodes properties for subsequent creations
 *
 */
public class OppNodeFactory implements NodeFactory {

	private final OppNodeProperties defaultProperties;  // default node properties
	private final OppNodeProfiles profiles;             // profiles and properties (may be null)

	// attributes for the subsequent node creations
	private OppNodeProperties properties;        // node properties
	private String profile;                      // profile name

	private CoordCar coord;                      // node location
	private String label;
	private NodeLabels labels;

	//-------------------------------------------------------------------------
	/**
	 * Constructor. Initialize the default properties and attributes for the
	 * subsequent node creations.
	 *
	 * @param props the default node properties
	 */
	public OppNodeFactory(OppNodeProperties props) {
		this.defaultProperties = props;
		this.properties = defaultProperties;
		this.profiles = props.getNodeProfiles();
		this.labels = props.getNodeLabels();
	}

	//-------------------------------------------------------------------------
	/**
	 * Create a {@link OppNode} instance.
	 *
	 * @param id the node id.
	 * @param g a {@link OppNetGraph}.
	 * @return the new node
	 */
	@Override
	public OppNode newInstance(String id, Graph g) {

		OppNetGraph graph = (OppNetGraph) g;

		String label = this.label;
		if (label == null && labels != null) {
			label = labels.getLabel(id);
		}

		String profile = this.profile;
		OppNodeProperties properties = this.properties;
		if (profile == null && this.profiles != null) {
			String key = label != null ? label : id;
			profile = this.profiles.getProfile(key);
			if (profile != null) {
				properties = profiles.getProperties(profile);
			}
		}

		Walk walk = properties.getWalk();
		boolean mobile = properties.isMobile();
		if (walk != null && mobile) {
			Walker walker = walk.getWalker(graph.getCurrentStep(), id);
			return new OppNode(graph, id, profile, properties, label, walker);
		} else {
			CoordCar nodeCoord = coord != null ? coord : properties.getCoord();
			return new OppNode(graph, id, profile, properties, label, nodeCoord);
		}
	}

	//-------------------------------------------------------------------------
	// Setters of the attributes for the subsequent node creations
	//-------------------------------------------------------------------------
	/**
	 * Set the profile for the subsequent node creations.
	 *
	 * @param profile
	 */
	public void setProfile(String profile) {

		if (Objects.equals(profile, this.profile)) {
			return;
		}
		if (profile != null && profiles == null) {
			System.err.println("Warning: unknown node profiles. Profile " + profile + " not found. Using default properties.");
			return;
		}

		OppNodeProperties props = null;
		if (profile != null) {

			props = profiles.getProperties(profile);
			if (props == null) {
				System.err.println("Warning: profile " + profile + " not found. Using default properties.");
			}
		}

		this.profile = profile;
		this.properties = props != null ? props : defaultProperties;
	}

	//-------------------------------------------------------------------------
	/**
	 * Set the label for the subsequent object creations.
	 *
	 * @param label node label
	 */
	public void setLabel(String label) {
		this.label = label;
	}

	//-------------------------------------------------------------------------
	/**
	 * Set the node location for the subsequent object creations.
	 *
	 * @param coord node location
	 */
	public void setCoord(CoordCar coord) {
		this.coord = coord;
	}
}
