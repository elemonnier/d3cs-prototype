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
import java.util.regex.Pattern;

/**
 * A map associating profile names to {@link OppNodeProperties} objects. The
 * profiles are loaded from a file which format is described in the
 * {@link ConfigurationProfiles} class.
 *
 */
public class OppNodeProfiles extends ConfigurationProfiles<OppNodeProperties> {

    //-------------------------------------------------------------------------
    /**
     * Loads profiles from a file where properties are introduced by their
     * profile name between '[' ']'. The properties defined before the first
     * profile name are properties common to all profiles.
     *
     * @param commonProperties properties common to all profiles. May be null.
     * Those common properties are overwritten by the specific profiles'
     * properties
     * @param reader input stream from which the properties are loaded
     * @throws IOException if an error occurs while accessing the input stream
     */
    public OppNodeProfiles(OppNodeProperties commonProperties, BufferedReader reader) throws IOException {
        super(commonProperties, reader);
    }

    public String getProfile(String id) {
        for (String profile : getProfiles()) {
            String prefix = getProperties(profile).getPrefix();
            if (id.startsWith(prefix)) {
                return profile;
            }
        }
        return null;
    }

    //-------------------------------------------------------------------------
    @Override
    protected OppNodeProperties makeProperties(Properties props) {
        return new OppNodeProperties(props);
    }
}
