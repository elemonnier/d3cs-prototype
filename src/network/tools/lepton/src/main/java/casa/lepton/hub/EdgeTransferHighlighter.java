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
package casa.lepton.hub;

import casa.lepton.OppNet;
import casa.lepton.OppNetGraph;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

final class EdgeTransferHighlighter {

    private static final String TRANSFER_TAG = "TRANSFER";
    private static final long TRANSFER_DURATION_MS = 2000;

    private static final AtomicLong NEXT_GENERATION = new AtomicLong();
    private static final ConcurrentHashMap<String, Long> GENERATIONS = new ConcurrentHashMap<>();
    private static final ScheduledExecutorService SCHEDULER
            = Executors.newSingleThreadScheduledExecutor((Runnable runnable) -> {
                Thread thread = new Thread(runnable, "lepton-edge-transfer-highlighter");
                thread.setDaemon(true);
                return thread;
            });

    private EdgeTransferHighlighter() {
    }

    static void highlight(OppNet oppNet, String source, String target) {
        if (!(oppNet instanceof OppNetGraph)
                || source == null || target == null
                || source.equals(target)) {
            return;
        }

        OppNetGraph graph = (OppNetGraph) oppNet;
        String edgeKey = graph.makeEdgeId(source, target, null);
        long generation = NEXT_GENERATION.incrementAndGet();

        graph.setEdgeTag(source, target, null, TRANSFER_TAG, true);
        GENERATIONS.put(edgeKey, generation);

        SCHEDULER.schedule(() -> {
            Long currentGeneration = GENERATIONS.get(edgeKey);
            if (currentGeneration != null && currentGeneration.longValue() == generation) {
                graph.setEdgeTag(source, target, null, TRANSFER_TAG, false);
                GENERATIONS.remove(edgeKey, currentGeneration);
            }
        }, TRANSFER_DURATION_MS, TimeUnit.MILLISECONDS);
    }
}
