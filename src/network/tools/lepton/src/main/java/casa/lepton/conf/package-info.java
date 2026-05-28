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
/**
 * This package provides classes that define properties for the different classes,
 * loaded from configuration files.
 *
 * There are two kinds of configuration files:
 * <ul>
 *
 * <li>Configuration files defining properties as "key=value" associations. They
 * are used to initialize {@link casa.util.conf.ConfigurationProperties}
 * objects</li>
 *
 * <li>Profile files defining profiles as groups of "key=value" associations.
 * Each group is preceded by a profile name between '[' and ']'. All properties
 * before the first profile name are common to all profiles. They are used to
 * initialize {@link casa.util.conf.ConfigurationProfiles} objects, that
 * provide {@link casa.util.conf.ConfigurationProperties} objects from profile
 * names</li>
 *
 * </ul>
 *
 * The properties provided by the
 * {@link casa.util.conf.ConfigurationProperties} objects are typed properties
 * initialized from their string representation in the configuration file.
 *
 * {@link casa.lepton.conf.OppNetProperties} define the properties used for the
 * graph (common properties) and {@link casa.lepton.conf.OppNodeProperties}
 * define the properties used for the nodes (different nodes may have different
 * properties).
 *
 * The keys used to define de property values are defined by the
 * {@link casa.util.conf.PropertyKey} enumeration. They have the same name in
 * downcase characters in the configuration files.
 *
 * In the configuration files, some values may contain variables in the form
 * <code>${var}</code> representing other properties defined either in the
 * configuration file or provided as command line arguments.
 *
 */
package casa.lepton.conf;
