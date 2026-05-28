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
package casa.lepton.conf;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Properties;

/**
 * Associations (nodeId,label) and (label,nodeId) loaded from a file that
 * contains "nodeId=label" lines.
 *
 * The labels are used as string representations of the nodes when displaying
 * the graph. If no label is provided, the nodeId is used instead
 *
 */
public class NodeLabels {

    private final Properties labels;    // (nodeId,label) associations
    private final Properties nodeIds;   // (label,nodeId) associations

    //-------------------------------------------------------------------------
    /**
     * Initialization from a properties input stream that contains nodeId,labels
     * associations
     *
     * @param reader the input stream
     * @throws IOException if an error occurs while accessing the input stream
     */
    public NodeLabels(BufferedReader reader) throws IOException {
        labels = new Properties();
        nodeIds = new Properties();
        labels.load(reader);
        for (String nodeId : labels.stringPropertyNames()) {
            nodeIds.put(labels.getProperty(nodeId), nodeId);
        }
    }

    //-------------------------------------------------------------------------
    /**
     * Give the label associated to the given nodeId. If this association
     * doesn't exist, return the nodeId
     *
     * @param nodeId nodeId
     * @return the label associated to the nodeId
     */
    public String getLabel(String nodeId) {
        String label = labels.getProperty(nodeId);
        if (label == null) {
            label = nodeId;
        }
        return label;
    }

    //-------------------------------------------------------------------------
    /**
     * Give the nodeId associated to the given label. If this association
     * doesn't exist, return the label
     *
     * @param label label
     * @return the nodeId associated to the label
     */
    public String getNodeId(String label) {
        String nodeId = nodeIds.getProperty(label);
        if (nodeId == null) {
            nodeId = label;
        }
        return nodeId;
    }
}
