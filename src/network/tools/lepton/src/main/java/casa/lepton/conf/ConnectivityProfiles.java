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

import casa.util.conf.ConfigurationProfiles;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Properties;
import java.util.Set;

/**
 * Profiles representing connectivity typeshaving each their
 * {@link ConnectivityProperties}.
 *
 */
public class ConnectivityProfiles extends ConfigurationProfiles<ConnectivityProperties> {

    //-------------------------------------------------------------------------
    /**
     * Create a {@link ConnectivityProfiles} instance without any profile, but
     * only default properties
     *
     * @param defaultProperties the default properties
     */
    public ConnectivityProfiles(Properties defaultProperties) {
        super(defaultProperties);
    }

    //-------------------------------------------------------------------------
    /**
     * Loads profiles from a file where properties are introduced by their
     * profile name between '[' ']'.
     *
     * @param reader input stream from which the properties are loaded
     */
    public ConnectivityProfiles(BufferedReader reader) throws IOException {
        super(reader);
    }

    //-------------------------------------------------------------------------
    /**
     * Gives all connectivity types having a range.
     *
     * @return a set of all connectivity types having a range.
     */
    public Set<String> getConnectivityTypes() {
        return getProfiles();
    }

    //-------------------------------------------------------------------------
    /**
     * Gives the range for a given connectivity type.
     *
     * @param type a connectivity type.
     * @return the range for this connectivity type.
     */
    public long getRange(String type) {
        if (type == null || !this.containsKey(type)) {
            return commonProperties.getRange();
        } else {
            return this.get(type).getRange();
        }
    }

    //-------------------------------------------------------------------------
    @Override
    protected ConnectivityProperties makeProperties(Properties props) {
        return new ConnectivityProperties(props);
    }
}
