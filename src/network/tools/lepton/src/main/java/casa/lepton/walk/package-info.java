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
 * This package is related to the mobility models for nodes moving in some areas.
 * A {@link casa.lepton.walk.Walk} represents some mobility model, and provides
 * {@link casa.lepton.walk.Walker} instances for each node that should move
 * according to this model. A node {@link casa.lepton.walk.Walker} gives the
 * location of the node from a given time. It relies the calculation of
 * {@link casa.lepton.walk.Step} instances that represent each a linear move
 * between two points called a 'flight', followed by a pause.
 *
 */
package casa.lepton.walk;
