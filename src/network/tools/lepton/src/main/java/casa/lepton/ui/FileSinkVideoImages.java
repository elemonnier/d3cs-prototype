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
package casa.lepton.ui;

import casa.lepton.OppNetGraph;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.LinkedList;
import java.util.Locale;
import java.util.TimeZone;
import javax.imageio.ImageIO;
import org.graphstream.stream.file.FileSinkImages;
import org.graphstream.ui.geom.Point3;

/**
 * Extends the GraphStream FileSinkImages class in order to allow to insert
 * specialized pre-renderers. Inserting specialized post-renderers was already
 * possible and was used for providing the addLogo method. In this version of
 * the class, a pre-renderer is implemented for providing the addBackground
 * method and a another post-renderer is implemented for providing the addTimer
 * method.
 *
 */
public class FileSinkVideoImages extends FileSinkImages {

    private static final DateFormat timeFormat = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());

    private static final OutputType OUTPUT_TYPE = OutputType.png;

    protected LinkedList<PreRenderer> preRenderers;

    // Graph from which the step events trigger image output
    private OppNetGraph oppNetGraph;

    // Time of the last output image
    private double lastImageTime = -1000.0;

    public FileSinkVideoImages(OppNetGraph graph) {
        this(OUTPUT_TYPE, Resolutions.SVGA, graph);
    }

    public FileSinkVideoImages(OutputType type, Resolution resolution, OppNetGraph graph) {
        this("frame_", type, resolution, OutputPolicy.NONE, graph);
    }

    public FileSinkVideoImages(String prefix, OutputType type,
            Resolution resolution, OutputPolicy outputPolicy, OppNetGraph graph) {
        super(prefix, type, resolution, outputPolicy);
        this.preRenderers = new LinkedList<PreRenderer>();
        this.oppNetGraph = graph;
        TimeZone timezone = oppNetGraph.getTimeZone();
        if (timezone != null) {
            timeFormat.setTimeZone(timezone);
        }
    }

    /**
     * This method was strangely lacking in FileSinkImages (appears in
     * gs-core-1.3)
     */
    /*

    @Override
    public void setGraphViewport(double minx, double miny, double maxx, double maxy) {
        this.renderer.getCamera().setGraphViewport(minx, miny, maxx, maxy);
    }

     */
    /**
     * Produce a new image.
     */
    @Override
    public void outputNewImage() {
        long curImageTime = oppNetGraph.getCurrentTime();
        // Don't generate images too close in time (1/60s)
        if ((curImageTime - this.lastImageTime) >= (1000.0 / 60.0)) {
            this.lastImageTime = curImageTime;
            outputNewImage(String.format("%s%09d.%s", filePrefix, curImageTime, OUTPUT_TYPE));
            //outputNewImage(String.format("%s%06d.%s", filePrefix, counter++, OUTPUT_TYPE));
            this.lastImageTime = curImageTime;
        }
    }

    /**
     * Almost identical to the original method in FileSinkImages. The only thing
     * added is the execution of the pre-renderers
     */
    @Override
    public synchronized void outputNewImage(String filename) {
        switch (layoutPolicy) {
            case COMPUTED_IN_LAYOUT_RUNNER:
                layoutPipeIn.pump();
                break;
            case COMPUTED_ONCE_AT_NEW_IMAGE:
                if (layout != null) {
                    layout.compute();
                }
                break;
            case COMPUTED_FULLY_AT_NEW_IMAGE:
                stabilizeLayout(layout.getStabilizationLimit());
                break;
            default:
                break;
        }

        if (resolution.getWidth() != image.getWidth()
                || resolution.getHeight() != image.getHeight()) {
            initImage();
        }

        if (clearImageBeforeOutput) {
            for (int x = 0; x < resolution.getWidth(); x++) {
                for (int y = 0; y < resolution.getHeight(); y++) {
                    image.setRGB(x, y, 0x00000000);
                }
            }
        }

        for (PreRenderer action : preRenderers) {
            action.render(g2d);
        }

        if (gg.getNodeCount() > 0) {
            if (autofit) {
                gg.computeBounds();

                Point3 lo = gg.getMinPos();
                Point3 hi = gg.getMaxPos();

                renderer.getCamera().setBounds(lo.x, lo.y, lo.z, hi.x, hi.y,
                        hi.z);
                System.err.println("Output setbounds(" + lo.x + ", " + lo.y + "," + lo.z + ", " + hi.x + ", " + hi.y + ", " + hi.z + ")");
            }

            renderer.render(g2d, 0, 0, resolution.getWidth(),
                    resolution.getHeight());
        }

        for (PostRenderer action : postRenderers) {
            action.render(g2d);
        }

        image.flush();

        try {
            File out = new File(filename);

            if (out.getParent() != null && !out.getParentFile().exists()) {
                out.getParentFile().mkdirs();
            }

            ImageIO.write(image, outputType.name(), out);

            printProgress();
        } catch (IOException e) {
            // ?
        }
    }

    /**
     * Post-rendering action to display the time in a corner of the image
     */
    public void addTimer(OppNetGraph graph, Corner corner) {

        PostRenderer pr;
        pr = new AddTimerDisplayRenderer(graph, corner);
        postRenderers.add(pr);
    }

    private class AddTimerDisplayRenderer implements PostRenderer {

        OppNetGraph ng;

        TitleBlock titleBlock;

        public AddTimerDisplayRenderer(OppNetGraph graph, Corner corner) {

            this.ng = graph;
            Graphics2D g2d = FileSinkVideoImages.this.g2d;
            int imgWidth = FileSinkVideoImages.this.resolution.getWidth();
            int imgHeight = FileSinkVideoImages.this.resolution.getHeight();

            // The size of the displayed time is computed with the time 00:00:00
            String sample = timeFormat.format(0);

            // Color
            System.err.println("Color=" + Color.getColor("time_fgcolor"));
            Color color = Color.getColor("time_fgcolor", Color.black);

            System.err.println("Background=" + Color.getColor("time_bgcolor"));
            Color background = Color.getColor("time_bgcolor");

            // Font
            Font font = Font.getFont("time_font", new Font("Sans", Font.BOLD, 18));

            this.titleBlock = new TitleBlock(g2d, new Rectangle(imgWidth, imgHeight), corner, sample, font, color, background);

        }

        public void render(Graphics2D g) {
            long time = AddTimerDisplayRenderer.this.ng.getCurrentTime();
            this.titleBlock.draw(timeFormat.format(time));
        }

    }

    /**
     * Defines pre rendering action on images.
     */
    public static interface PreRenderer {

        void render(Graphics2D g);
    }

    /**
     * Pre rendering action allowing to add a background picture on images.
     */
    public void addBackground(File backgroundFile, int sinkWidth, int sinkHeight) {
        try {
            PreRenderer pr;

            pr = new AddBackgroundRenderer(backgroundFile, sinkWidth, sinkHeight);
            preRenderers.add(pr);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    protected static class AddBackgroundRenderer implements PreRenderer {

        BufferedImage backgroundImg;
        AffineTransform transform;

        public AddBackgroundRenderer(File backgroundFile, int sinkWidth, int sinkHeight)
                throws IOException {

            if (backgroundFile.exists()) {
                this.backgroundImg = ImageIO.read(backgroundFile);
            } else {
                this.backgroundImg = ImageIO.read(ClassLoader.getSystemResource(backgroundFile.toString()));
            }

            double sx = (double) sinkWidth / backgroundImg.getWidth();
            double sy = (double) sinkHeight / backgroundImg.getHeight();

            transform = new AffineTransform();
            transform.setToTranslation(0, 0);
            transform.scale(sx, sy);
            System.err.println("Output background transform scale = " + sx + "," + sy);
        }

        public void render(Graphics2D g) {
            g.drawImage(backgroundImg, transform, null);
        }
    }
}
