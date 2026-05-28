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
import casa.lepton.conf.OppNetProperties;
import casa.util.geom.AreaCar;
import java.io.File;
import java.io.IOException;
import org.graphstream.stream.file.FileSinkImages.RendererType;

/**
 * Class used to generate images from a LEPTON execution in order to make
 * videos.
 *
 */
public class OppNetOutput {

    private File imgDir = null;
    private FileSinkVideoImages sink_;
    private String image_;

    // the area covered by the image to be displayed in the background
    private AreaCar viewportArea_;

    private OppNetGraph graph_;

    public OppNetOutput(OppNetGraph graph, OppNetProperties props) {
        System.err.println("Creating OppNetOutput");
        graph_ = graph;

        imgDir = props.getVideoImgDir();
        if (!imgDir.exists()) {
            imgDir.mkdirs();
        }

        String imgRes = props.getResolution();
        if (imgRes == null) {
            System.err.println("Output resolution not specified. Will use SVGA by default...");
            imgRes = "SVGA";
        }

        FileSinkVideoImages.Resolution resolution = null;
        try {
            resolution = FileSinkVideoImages.Resolutions.valueOf(imgRes);
        } catch (Exception e) {
            String[] fields = imgRes.split("x");
            if (fields.length == 2) {
                int width = Integer.parseInt(fields[0]);
                int height = Integer.parseInt(fields[1]);
                resolution
                        = new FileSinkVideoImages.CustomResolution(width, height);
            }
            if (resolution == null) {
                System.err.println("Failed to set resolution at \""
                        + resolution + "\"");
                throw e;
            }
        }

        FileSinkVideoImages.OutputPolicy outputPolicy = FileSinkVideoImages.OutputPolicy.BY_STEP;
        //FileSinkVideoImages.OutputPolicy outputPolicy = FileSinkVideoImages.OutputPolicy.ON_RUNNER;
        FileSinkVideoImages.OutputType type = FileSinkVideoImages.OutputType.PNG;

        sink_ = new FileSinkVideoImages(type, resolution, graph_);

        sink_.setOutputPolicy(outputPolicy);

        // Avoid superposition of images if the background is transparent
        // Not useful if there is a background
        boolean stackImages = props.getStackImages();
        File bkgImage = props.getBackgroundImage();
        if (bkgImage == null && !stackImages) {
            sink_.setClearImageBeforeOutputEnabled(true);
        }

        //sink_.setLayoutPolicy(FileSinkVideoImages.LayoutPolicy.COMPUTED_FULLY_AT_NEW_IMAGE);
        //sink_.setLayoutPolicy(FileSinkVideoImages.LayoutPolicy.COMPUTED_IN_LAYOUT_RUNNER);
        sink_.setQuality(FileSinkVideoImages.Quality.HIGH);

        // sink_.setStyleSheet("graph { padding: 50px; fill-color: black; }"
        // 		       + "node { fill-color: #3d5689; }"
        // 		       + "edge { fill-color: white; }");
        sink_.setRenderer(RendererType.SCALA);

        setViewportArea(props.getBackgroundArea());

        if (viewportArea_ == null) {
            sink_.setAutofit(true);
        } else {
            sink_.setAutofit(false);
            sink_.setViewCenter(viewportArea_.x + viewportArea_.width / 2,
                    viewportArea_.y + viewportArea_.height / 2);

            sink_.setGraphViewport(viewportArea_.x, viewportArea_.y,
                    viewportArea_.x + viewportArea_.width,
                    viewportArea_.y + viewportArea_.height);
        }

        sink_.setStyleSheet(props.getStylesheet());
        // Force padding to 0 for this graphic graph
        // (à enlever quand on pourra produire des images de fonds de carte incluant un padding
        sink_.setStyleSheet("graph { padding:0; }");

        Corner corner = props.getTimeCorner();
        System.err.println("Adding timer in corner " + corner);
        if (corner != null) {
            sink_.addTimer(graph_, corner);
        }

        System.err.println("Adding Ouput background image=" + bkgImage);
        if (bkgImage != null) {
            sink_.addBackground(bkgImage, resolution.getWidth(), resolution.getHeight());
        }

        // sink_.setOutputRunnerEnabled(true);

        graph_.addSink(sink_);
    }

    // ------------------------------------------------------------------------
    /**
     * Compute the area to display and adjust the simulation area accordingly if
     * possible
     *
     * @param backgroundArea the area to display
     */
    // TODO see the same method in OppNetFrame
    private void setViewportArea(AreaCar backgroundArea) {

        AreaCar simulArea = graph_.getArea();

        if (backgroundArea != null) {

            this.viewportArea_ = backgroundArea;

            // adjust the simulation area if possible
            if (simulArea == null) {
                simulArea = backgroundArea;
                graph_.setArea(simulArea);
            } else if (simulArea.hasref) {
                backgroundArea.setRef(simulArea.reflat, simulArea.reflon);
            }

        } else {
            this.viewportArea_ = simulArea;
        }
    }

    public void start() throws IOException {
        String path = new File(imgDir, "img_").getAbsolutePath();
        System.err.println("Output path: " + path);
        sink_.begin(path);
    }

}
