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
package casa.lepton.console;

import casa.lepton.OppNet;

/**
 * All methods names in the {@link OppNet} interface and their abbreviations to
 * be used as text commands.
 *
 */
public enum OppNetCommand {

    addNode("an"),
    deleteNode("dn"),
    isNode("in"),
    getNodes("gn"),
    setOnline("so"),
    isOnline("io"),
    setTag("st"),
    getTag("gt"),
    addConnectivityType("at"),
    removeConnectivityType("rt"),
    setNodeStatus("sns"),
    getNodeStatus("gns"),
    setEdgeStatus("ses"),
    getEdgeStatus("ges"),
    getNeighbors("gne"),
    areNeighbors("ane"),
    makeEdgeId("mei"),
    addEdgeListener("ael"),
    removeEdgeListener("rel"),
    addNodeListener("anl"),
    removeNodeListener("rnl"),
    UNKNOWN("un");

    private String abbr;

    OppNetCommand(String abbr) {
        this.abbr = abbr;
    }

    public String getAbbr() {
        return abbr;
    }
}
