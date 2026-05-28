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

import casa.util.conf.PropertyKey;
import casa.util.conf.ConfigurationProperties;
import static casa.lepton.conf.ConnectivityPropertyKey.RANGE;
import java.util.Arrays;
import java.util.Properties;

/**
 * Properties for connectivity types: ranges, scanning delays, connection
 * delays.
 *
 */
public class ConnectivityProperties extends ConfigurationProperties {

    private static final PropertyKey[] KEYS = {RANGE};

    //-------------------------------------------------------------------------
    public ConnectivityProperties(Properties props) {
        super(props, Arrays.asList(KEYS));
        expandVariables(props);
    }

    //-------------------------------------------------------------------------
    @Override
    protected Object getTypedValue(PropertyKey key) {
        if (key == RANGE) {
            return getRange();
        }
        return null;
    }

    //-------------------------------------------------------------------------
    /**
     * Gives the radio range for this connectivity type (in m).
     *
     * @return the range for this connectivity type.
     */
    public long getRange() {
        return getLongProperty(RANGE);
    }
}
