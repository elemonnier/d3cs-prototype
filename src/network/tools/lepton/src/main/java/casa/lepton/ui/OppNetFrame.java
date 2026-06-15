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
import casa.lepton.OppNode;
import casa.lepton.conf.OppNetProperties;
import casa.dgs.DGSGraph;
import casa.lepton.OppEdge;
import casa.util.geom.AreaCar;
import casa.util.geom.CoordCar;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.Stroke;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseMotionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.text.DateFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.imageio.ImageIO;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import static javax.swing.JOptionPane.CANCEL_OPTION;
import static javax.swing.JOptionPane.NO_OPTION;
import static javax.swing.JOptionPane.YES_OPTION;
import javax.swing.JPanel;
import javax.swing.JToggleButton;
import javax.swing.Timer;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.graphstream.ui.graphicGraph.GraphPosLengthUtils;
import org.graphstream.ui.graphicGraph.GraphicGraph;
import org.graphstream.ui.swingViewer.DefaultView;
import org.graphstream.ui.swingViewer.LayerRenderer;
import org.graphstream.ui.swingViewer.ViewPanel;
import org.graphstream.ui.view.Camera;
import org.graphstream.ui.view.Viewer;
import org.graphstream.ui.view.Viewer.ThreadingModel;
import org.graphstream.ui.view.ViewerListener;
import org.graphstream.ui.view.ViewerPipe;

/**
 * A frame used to display and control a {@link OppNetGraph}. When the frame is
 * displayed, the simulation is started. Buttons allows to stop/resume the
 * simulation and open/close a console.
 *
 * Mouse clicks on nodes moving on the frame allow to tag/untag nodes.
 *
 * A background image or a background graph can be displayed on the frame. The
 * image zoom is controled by the up/down keys.
 *
 */
public class OppNetFrame extends JFrame implements ViewerListener {

	private static final int NONE_MODE = 0, NODE_TAGGING_MODE = 1, NODE_DRAGGING_MODE = 2, EDGE_DRAWING_MODE = 4;
	private static final NumberFormat NUMBER_FORMAT = NumberFormat.getInstance(Locale.getDefault());
	private static final DateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
	private static final DateFormat SHORT_TIME_FORMAT = new SimpleDateFormat("mm:ss", Locale.getDefault());

	static {
		NUMBER_FORMAT.setMinimumFractionDigits(2);
		NUMBER_FORMAT.setMaximumFractionDigits(2);
	}

	private final OppNetGraph oppNetGraph;  // the graph to be displayed
	private final boolean manual;           // true if the simulation is in manual mode
	private final boolean makeEdges;        // true if the edges representing the contacts must be computed in mal=nual mode

	private AreaCar viewportArea;           // the area covered by the image to be displayed in the background
	private Camera camera;                  // the camera associated with the View (used only if the area is not null)
	private Viewer viewer;
	private ViewerPipe graphViewerPipe;     // to catch clicks on nodes in the graph

	// the panels
	private JPanel southPanel;              // for buttons and timer
	private ViewPanel graphPanel;           // to display the graph
	private JPanel eastPanel;               // informations about the simulation

	// the console properties
	private JButton buttonConsole;          // the button to open/close the console
	private final int consolePort;          // the console port number
	private boolean consoleVisible;         // true if the console frame is visible
	private JDialog consoleFrame;           // the console frame
	private JPanel consolePanel;            // the panel in the console frame

	// start/stop the simulation
	private JButton buttonStartStop;        // the button to start/stop the simulation
	private Icon startIcon, stopIcon;       // the icons in the start/stop button
	private boolean started;                // whether the nodes are moving or not

	// time & accel
	private JButton speedupButton;          // button to speed up the simulation
	private JButton slowdownButton;         // button to slow down the simulation
	private JLabel accelLabel;              // to display the simulation acceleration
	private JLabel elapsedLabel;            // to display the elapsed time
	private Timer timer;                    // timer to refresh the timeLabel
	private String currentTime;             // a string representation of the current simulation time
	private String elapsedTime;             // a string representation of the time elapsed since the beginning of the simulation
	private long refTime;

	// background
	private DGSGraph backgroungGraph;       // the background graph (may be null)
	private File backgroundImageFile;       // main background image file at zoom 1 (may be null)
	private TreeSet<ZoomedImage> backgroundImages; // the background images with their corresponding zoom
	private BufferedImage currentBackgroundImage;  // the background image currently displayed

	// time on the background
	private Color timeFgColor;              // the time color
	private Color timeBgColor;              // the time background color
	private Font timeFont;                  // the font of the time text
	private Corner timeCorner;              // the location of the time on the background image

	// properties for the {@link LayerRenderer} classes, updated at each
	// {@link LayerRenderer#render(Graphics2D, GraphicGraph, double, int, int, double, double, double, double)}
	// invocation
	private int widthPx, heightPx;          // the size in pixels of the graph view port
	private double px2Gu;                   // the ratio to pass from pixels to graph units
	private double width, height;
	private double deltaX, deltaY;
	private long lastRender;                // the last time the graph has been painted (rendered)

	// mode: EDGE_DRAWING, NODE_DRAGGING, NODE_TAGGING
	private int mode;
	private boolean edgeDrawingEnabled;     // true if edge drawing is enabled
	private EdgeDrawer edgeDrawer;          // instance used to draw edges
	private boolean nodeDraggingEnabled;    // true if node dragging is enabled
	private Set<MouseMotionListener> nodeDraggingListeners;  // the listener(s) that Make the node dragging
	private boolean nodeTaggingEnabled;     // true if node tagging is enabled
	private boolean autoLayoutEnabled;      // true if autolayout is enabled

	private boolean buttonDragged;          // true if a node has been dragged

	//-------------------------------------------------------------------------
	// Frame with or without a background image or a background graph
	//
	public OppNetFrame(OppNetGraph oppNetGraph, OppNetProperties props) {
		// frame properties
		setLayout(new BorderLayout());
		setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent we) {
			    onWindowClosing();
			}
		});
		//        setSize(1024, 768);
		setSize(1200, 800);
		setLocationByPlatform(true);

		nodeDraggingEnabled = true; // this is the default mode
		mode = NODE_DRAGGING_MODE;

		System.setProperty("org.graphstream.ui.renderer",
		                   "org.graphstream.ui.j2dviewer.J2DGraphRenderer");

		this.oppNetGraph = oppNetGraph;
		this.consolePort = props.getConsolePort();
		this.manual = props.isManual();
		this.makeEdges = props.makeEdges();

		this.timeCorner = props.getTimeCorner();
		this.timeFgColor = props.getTimeFgColor();
		this.timeBgColor = props.getTimeBgColor();
		this.timeFont = props.getTimeFont();

		this.timer = makeTimer();
		this.refTime = oppNetGraph.getRefTime();
		long time = oppNetGraph.getCurrentTime();
		this.currentTime = format(time);
		this.elapsedTime = format(time - refTime);

		TimeZone timezone = oppNetGraph.getTimeZone();
		if (timezone != null) {
			System.out.println("timezone: " + timezone.getID());
			TIME_FORMAT.setTimeZone(timezone);
			SHORT_TIME_FORMAT.setTimeZone(timezone);
		}

		File imageFile = props.getBackgroundImage();
		String backgroundDGS = props.getBackgroundGraph();
		AreaCar backgroundArea = props.getBackgroundArea();

		if (imageFile != null) {

			initBackgroundImages(imageFile);

		}

		if (backgroundDGS != null) {

			try {
				this.backgroungGraph = new DGSGraph("bg", backgroundDGS);
				backgroungGraph.initGraph();
				AreaCar graphArea = backgroungGraph.getArea();
				if (graphArea != null) {
					backgroundArea = graphArea;
				}
			} catch (IOException ex) {
				System.err.println("Failed to load background graph from " + backgroundDGS);
			}

		}

		setViewportArea(backgroundArea);
		oppNetGraph.addAttribute("ui.antialias");

		// init panels
		initCenterPanel();
		initSouthPanel();
		initEastPanel();

		if (!manual) {
			// disable nodes dragging & enable tagging
			setMode(NODE_TAGGING_MODE);
		} else {
			// enable nodes dragging & tagging
			setMode(NODE_TAGGING_MODE | NODE_DRAGGING_MODE);
		}
	}

	private void onWindowClosing() {
		if (!oppNetGraph.hasNext()) {
			this.dispose();
			oppNetGraph.close();
		} else {
			int option = JOptionPane.showConfirmDialog(this, "The simulation is still running. Do you want to kill the simulation as well?");
			switch (option) {
			case YES_OPTION:
				this.dispose();
				oppNetGraph.close();
			case NO_OPTION:
				this.dispose();
			case CANCEL_OPTION:
				// DO NOTHING
			}
		}
	}

	// ------------------------------------------------------------------------
	/**
	 * Compute the area to display and adjust the simulation area accordingly if
	 * possible
	 *
	 * @param backgroundArea the area to display
	 */
	private void setViewportArea(AreaCar backgroundArea) {

		AreaCar simulArea = oppNetGraph.getArea();

		if (backgroundArea != null) {

			this.viewportArea = backgroundArea;

			// adjust the simulation area if possible
			if (simulArea == null) {
				simulArea = backgroundArea;
				oppNetGraph.setArea(simulArea);
			} else if (simulArea.hasref) {
				backgroundArea.setRef(simulArea.reflat, simulArea.reflon);
			}

		} else {
			this.viewportArea = simulArea;
		}

		System.out.println("Areas: simulation: " + simulArea);
		System.out.println("       viewport:   " + viewportArea);
	}

	// ------------------------------------------------------------
	@Override
	public void setVisible(boolean visible) {
		super.setVisible(visible);

		if (visible) {
			// set the layer renderer for the background
			LayerRenderer backLayerRenderer;

			if (this.backgroundImageFile != null) {

				// Set the size of the frame according to the zoom 1 image
				BufferedImage img = getBackgroundImage();
				this.setSize(img.getWidth() + 4, img.getHeight() + 71);
				//                backLayerRenderer = new ImageLayerRenderer();
			}
			//            } else if (backgroungGraph != null) {
			//
			//                backLayerRenderer = new GraphLayerRenderer(backgroungGraph);
			//
			//            } else {
			backLayerRenderer = new BackLayerRenderer();

			//            }
			if (graphPanel instanceof DefaultView) {
				DefaultView defaultView = (DefaultView) graphPanel;
				defaultView.setBackLayerRenderer(backLayerRenderer);
			}
		}
	}
	// ------------------------------------------------------------

	/**
	 * Set the action mode: NODE_TAGGING_MODE, NODE_DRAGGING_MODE,
	 * EDGE_DRAWING_MODE. It is possible to combine those modes (e.g.
	 * NODE_TAGGING_MODE | NODE_DRAGGING_MODE) but not advisable
	 *
	 * @param mode the new mode
	 */
	private void setMode(int mode) {
		if (mode != this.mode) {
			this.mode = mode;
			enableNodeTagging((mode & NODE_TAGGING_MODE) != 0);
			enableNodeDragging((mode & NODE_DRAGGING_MODE) != 0);
			enableEdgeDrawing((mode & EDGE_DRAWING_MODE) != 0);
		}
	}

	// ------------------------------------------------------------
	/**
	 * Enable or disable the ability to tag nodes by clicking on them. Node
	 * dragging should be disabled before enabling node tagging
	 *
	 * @param enable true if node tagging should be enabled
	 */
	private void enableNodeTagging(boolean enable) {
		if (nodeTaggingEnabled != enable) {
			nodeTaggingEnabled = enable;
			if (enable) {
				this.graphViewerPipe.addViewerListener(this);
			} else {
				this.graphViewerPipe.removeViewerListener(this);
			}
		}
	}

	// ------------------------------------------------------------
	/**
	 * Enable or disable the ability to move nodes by dragging them
	 *
	 * @param enable true if node dragging should be enabled
	 */
	private void enableNodeDragging(boolean enable) {
		if (enable != nodeDraggingEnabled) {
			nodeDraggingEnabled = enable;
			if (!enable) {
				nodeDraggingListeners = new HashSet<>();
				for (MouseMotionListener listener : graphPanel.getMouseMotionListeners()) {
					graphPanel.removeMouseMotionListener(listener);
					nodeDraggingListeners.add(listener);
				}
			} else if (nodeDraggingListeners != null) {
				for (MouseMotionListener listener : nodeDraggingListeners) {
					graphPanel.addMouseMotionListener(listener);
				}
			}
		}
	}

	// ------------------------------------------------------------
	/**
	 * Enable or disable the ability to draw edges by dragging them. Node
	 * dragging should be disabled before enabling edge drawing
	 *
	 * @param enable true if edge drawing should be enabled
	 */
	private void enableEdgeDrawing(boolean enable) {
		if (enable != edgeDrawingEnabled) {
			edgeDrawingEnabled = enable;
			if (enable) {
				edgeDrawer = new EdgeDrawer(this);
				edgeDrawer.enable(enable);
			} else if (edgeDrawer != null) {
				edgeDrawer.enable(enable);
				edgeDrawer = null;
			}
		}
	}

	// ------------------------------------------------------------
	/**
	 * Enable or disable the auto layout of the nodes
	 *
	 * @param enable true if autolayout should be enabled
	 */
	private void enableAutoLayout(boolean enable) {
		if (enable != autoLayoutEnabled) {
			autoLayoutEnabled = enable;
			if (enable) {
				viewer.enableAutoLayout();
			} else {
				viewer.disableAutoLayout();
			}
		}
	}

	//-------------------------------------------------------------------------
	// Getters (for package only)
	//-------------------------------------------------------------------------
	ViewPanel getGraphPanel() {
		return graphPanel;
	}

	long lastRender() {
		return lastRender;
	}

	ViewerPipe getGraphViewerPipe() {
		return graphViewerPipe;
	}

	OppNetGraph GetOppNetGraph() {
		return oppNetGraph;
	}

	//---------------------------------------------------------------------
	CoordCar getCoord(Node node) {
		int x = 0, y = 0;
		double[] position = GraphPosLengthUtils.nodePosition(node);
		if (position.length > 1) {
			if (viewportArea != null) {
				x = (int) Math.round(px2Gu * (position[0] - viewportArea.x) + deltaX);
				y = (int) Math.round(px2Gu * (viewportArea.y + viewportArea.height - position[1]) + deltaY);
			} else {
				x = (int) Math.round(px2Gu * position[0] + deltaX);
				y = (int) Math.round(height - px2Gu * position[1] + deltaY);
			}
		}
		return new CoordCar(x, y);
	}

	//-------------------------------------------------------------------------
	// Frame initialization
	//-------------------------------------------------------------------------
	/**
	 * Initialize the center panel with the graph view
	 */
	private void initCenterPanel() {
		viewer = new Viewer(oppNetGraph, ThreadingModel.GRAPH_IN_ANOTHER_THREAD);

		this.graphPanel = viewer.addDefaultView(false);
		this.graphPanel.setBackground(Color.white);

		this.add(graphPanel, BorderLayout.CENTER);

		this.camera = this.graphPanel.getCamera();
		System.out.println("viewportArea: " + viewportArea);
		if (viewportArea == null) {
			System.out.println("Enable auto layout");
			enableAutoLayout(true);
		} else {
			System.out.println("Do not enable auto layout");
			enableAutoLayout(false);
			this.camera.setViewCenter(viewportArea.x + viewportArea.width / 2,
			                          viewportArea.y + viewportArea.height / 2,
			                          0);

			this.camera.setGraphViewport(viewportArea.x, viewportArea.y,
			                             viewportArea.x + viewportArea.width,
			                             viewportArea.y + viewportArea.height);
		}

		// viewerPipe to catch clicks on nodes
		this.graphViewerPipe = viewer.newViewerPipe();
		this.graphViewerPipe.addAttributeSink(oppNetGraph);
	}

	/**
	 * Initialize the south panel with the buttons and time label
	 */
	private void initSouthPanel() {
		this.southPanel = new JPanel(new BorderLayout());

		this.add(southPanel, BorderLayout.SOUTH);
		JPanel leftPanel = new JPanel(new FlowLayout());
		southPanel.add(leftPanel, BorderLayout.WEST);
		JPanel rightPanel = new JPanel(new FlowLayout());
		southPanel.add(rightPanel, BorderLayout.EAST);

		// console button
		buttonConsole = makeConsoleButton();
		leftPanel.add(buttonConsole);

		if (!manual) {

			// acceleration & start/stop button
			slowdownButton = makeAccelButton(false);
			leftPanel.add(slowdownButton);
			buttonStartStop = makeStartStopButton();
			leftPanel.add(buttonStartStop);
			speedupButton = makeAccelButton(true);
			leftPanel.add(speedupButton);
			accelLabel = makeAccelLabel();
			leftPanel.add(accelLabel);
			leftPanel.add(new JLabel("/"));
			elapsedLabel = makeElapsedLabel();
			leftPanel.add(elapsedLabel);

		} else if (!makeEdges) {
			//            JToggleButton layoutButton = makeLayoutButton();
			//            rightPanel.add(layoutButton);
			JToggleButton edgeButton = makeEdgeButton();
			rightPanel.add(edgeButton);
		}

		// background color
		this.southPanel.setBackground(Color.white);
		leftPanel.setBackground(Color.white);
		rightPanel.setBackground(Color.white);
	}

	/**
	 * Initialize the east panel with informations about the simulation
	 */
	private void initEastPanel() {

		this.eastPanel = new DetailsPanel(this.oppNetGraph);
		this.add(eastPanel, BorderLayout.EAST);
	}

	//-------------------------------------------------------------------------
	// Console
	//-------------------------------------------------------------------------
	/**
	 * Open a new dialog frame to communicate with the console
	 */
	private void openConsole() {
		if (consoleFrame == null && consolePort > 0) {
			try {
				consoleFrame = new JDialog(this, false);
				consolePanel = new ConsolePanel(consolePort);
				consoleFrame.setUndecorated(true);
				consoleFrame.add(consolePanel);
				consoleFrame.pack();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
		if (consoleFrame != null) {
			consoleVisible = !consoleVisible;
			if (consoleVisible) {
				setLocation(consoleFrame);
			}
			consoleFrame.setVisible(consoleVisible);
		}
	}

	/**
	 * Set the best location for the given dialog according to the main frame
	 * location
	 *
	 * @param dialog a dialog to be opened at the bottom left of the frame
	 */
	private void setLocation(JDialog dialog) {
		java.awt.Rectangle frameBounds = this.getBounds();
		int x = frameBounds.x + 80;
		int y = frameBounds.y + frameBounds.height;
		int height = dialog.getSize().height;
		int screenHeight = Toolkit.getDefaultToolkit().getScreenSize().height;
		if (y + height > screenHeight) {
			y = screenHeight - height;
		}
		dialog.setLocation(x, y);
	}

	/**
	 * Create a button to open/close the console
	 *
	 * @return the new button
	 */
	private JButton makeConsoleButton() {
		URL url = OppNetFrame.class.getResource("/images/btn_console.png");
		Icon icon = new ImageIcon(url);
		JButton consoleButton = makeButton(icon, "open/close console", new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
			    openConsole();
			}
		});;
		consoleButton.setBackground(Color.black);
		consoleButton.setForeground(Color.black);
		consoleButton.setEnabled(oppNetGraph.hasConsole());
		return consoleButton;
	}

	//-------------------------------------------------------------------------
	// Start/stop
	//-------------------------------------------------------------------------
	/**
	 * Start playing the simulation.
	 */
	public void start() {
		if (!started) {
			startStop();
		}
	}

	/**
	 * Stop playing the simulation.
	 */
	public void stop() {
		if (started) {
			startStop();
		}
	}

	/**
	 * Stop the simulation in such a way that it will not be possible to start
	 * it again.
	 */
	public void end() {
		stop();
		buttonStartStop.setEnabled(false);
	}

	/**
	 * Start or stop the simulation occording to its current status.
	 */
	private void startStop() {
		if (started) {
			oppNetGraph.stop();
			timer.stop();
		} else {
			oppNetGraph.play();
			timer.start();
		}
		started = !started;
		if (buttonStartStop != null) {
			buttonStartStop.setIcon(started ? stopIcon : startIcon);
		}
	}

	/**
	 * Create a button to start/stop the simulation.
	 *
	 * @return the new button
	 */
	private JButton makeStartStopButton() {
		// make icons
		URL url = OppNetFrame.class.getResource("/images/btn_stop.png");
		this.stopIcon = new ImageIcon(url);
		url = OppNetFrame.class.getResource("/images/btn_play.png");
		this.startIcon = new ImageIcon(url);
		Icon icon = started ? stopIcon : startIcon;

		// make button and listener
		return makeButton(icon, "start/stop simulation", new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
			    startStop();
			}
		});
	}

	/**
	 * Create a button
	 *
	 * @param icon the image o the button
	 * @param text the tooltip text
	 * @param listener the action listener
	 * @return the new button
	 */
	private JButton makeButton(Icon icon, String text, ActionListener listener) {
		JButton button = new JButton(icon);
		button.setToolTipText(text);
		button.addActionListener(listener);
		return button;
	}

	//-------------------------------------------------------------------------
	// Acceleration
	//-------------------------------------------------------------------------
	/**
	 * Make a button to change the acceleration
	 *
	 * @param speedUp true if the action of the button increases the
	 * acceleration
	 * @return the new button
	 */
	private JButton makeAccelButton(boolean speedUp) {
		String iconName = speedUp ? "btn_ff" : "btn_rew";
		URL url = OppNetFrame.class.getResource("/images/" + iconName + ".png");
		Icon icon = new ImageIcon(url);
		String text = speedUp ? "speed up" : "slow down";
		return makeButton(icon, text, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
			    changeAccel(speedUp);
			}
		});
	}

	/**
	 * Change the simulation acceleration.
	 *
	 * @param speedUp true if the acceleration must be increased
	 */
	private void changeAccel(boolean speedUp) {
		double accel = oppNetGraph.getAccel();
		double newAccel = speedUp ? accel * 2 : accel / 2;
		accelLabel.setText(NUMBER_FORMAT.format(newAccel) + " x");
		oppNetGraph.setAccel(newAccel);
	}

	/**
	 * Make the label to display the acceleration in the south panel.
	 *
	 * @return the new label
	 */
	private JLabel makeAccelLabel() {
		JLabel label = new JLabel(NUMBER_FORMAT.format(oppNetGraph.getAccel()) + " x");
		label.setBackground(Color.white);
		return label;
	}

	/**
	 * Make the label to display the acceleration in the south panel.
	 *
	 * @return the new label
	 */
	private JLabel makeElapsedLabel() {
		JLabel label = new JLabel(elapsedTime);
		label.setBackground(Color.white);
		return label;
	}

	//-------------------------------------------------------------------------
	// Edge drawing
	//-------------------------------------------------------------------------
	//    private JToggleButton makeLayoutButton() {
	//        URL url = OppNetFrame.class.getResource("/images/btn_layout.png");
	//        Icon icon = new ImageIcon(url);
	//        JToggleButton button = new JToggleButton(icon, autoLayoutEnabled);
	//        button.setToolTipText("enable/disable auto layout");
	//        button.addActionListener(new ActionListener() {
	//            @Override
	//            public void actionPerformed(ActionEvent ae) {
	//                enableAutoLayout(button.isSelected());
	//            }
	//        });
	//        return button;
	//    }
	//-------------------------------------------------------------------------
	private JToggleButton makeEdgeButton() {
		URL url = OppNetFrame.class.getResource("/images/btn_edge.png");
		Icon icon = new ImageIcon(url);
		JToggleButton button = new JToggleButton(icon, false);
		button.setToolTipText("add/delete edge");
		button.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
			    if (button.isSelected()) {
			        // remove all tags
			        pump(); // to update the nodes coords
			        setMode(EDGE_DRAWING_MODE);
				} else {
			        setMode(NODE_DRAGGING_MODE | NODE_TAGGING_MODE);
				}
			}
		});
		return button;
	}

	//-------------------------------------------------------------------------
	// Time
	//-------------------------------------------------------------------------
	/**
	 * Make a timer that updates the time to be displayed on the frame every
	 * second
	 *
	 * @return the timer
	 */
	private Timer makeTimer() {
		return new Timer(1000, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
			    tick();
			}
		});
	}

	/**
	 * Update the time to be displayed on the frame. Called every second
	 */
	private synchronized void tick() {
		long time = oppNetGraph.getCurrentTime();
		this.currentTime = format(time);
		this.elapsedTime = format(time - refTime);
		refreshDynamicNodeLabels();
		graphPanel.repaint(); // force the time display to be updated, but also the whole graph (?)
	}

	private void refreshDynamicNodeLabels() {
		for (Node node : oppNetGraph.getNodeSet()) {
			if (node instanceof OppNode) {
				((OppNode) node).refreshDynamicLabel();
			}
		}
	}

	private synchronized String getCurrentTime() {
		return currentTime;
	}

	private synchronized String getElapsedTime() {
		return elapsedTime;
	}

	/**
	 * Give a string representation of the given time
	 */
	private String format(long time) {
		if (time < 3600000) {
			return SHORT_TIME_FORMAT.format(time);
		}
		return TIME_FORMAT.format(time);
	}

	//-------------------------------------------------------------------------
	// ViewerListener that catch mouse events to tag nodes
	//-------------------------------------------------------------------------
	@Override
	public void viewClosed(String nodeId) {
		// DO NOTHING
	}

	@Override
	public void buttonPushed(String nodeId) {
		this.buttonDragged = false;
	}

	/**
	 * Add/remove the 'TAG' tag for the selected node.
	 */
	@Override
	public void buttonReleased(String nodeId) {
		if (!this.buttonDragged) {
			OppNode node = oppNetGraph.getNode(nodeId);
			if (node != null) {
				String tag = node.getTag();
				if (tag == null) {
					node.setTag("TAG");
				} else if (tag.equals("TAG")) {
					node.setTag(null);
				} else if (tag.contains("TAG")) {
					node.setTag(tag.replaceAll(",TAG|TAG,", ""));
				} else {
					node.setTag(tag + ",TAG");
				}
			}
		}
        this.buttonDragged = false;
	}

	/**
	 * Allows the viewer to catch mouse event.
	 */
	public void pump() {
		this.graphViewerPipe.pump();
	}

	//-------------------------------------------------------------------------
	// Images
	//-------------------------------------------------------------------------
	/**
	 * Initializes the set of background images. The main image is expected to
	 * be the image at zoom 1 The images at different zoom levels have the same
	 * type, and are expected to be present in files in the same directory.
	 * These files have the same prefix as the main image, followed by @n where
	 * n is a zoom level (as a float) For example, with a main image
	 * "background.png" two other images may be present with the names
	 * "background@2.png" and "background@0.5.png". For sake of consistency, the
	 * main image may have a prefix ending with @1 (or @01.0, @1.00 ...), in
	 * which case this @n is ignored when searching for other images
	 *
	 * @param img the image at zoom 1
	 */
	private void initBackgroundImages(File img) {

		if (img == null) {
			return;
		}

		this.backgroundImages = new TreeSet<>();

		// Take the parameter as the main (zoom 1) image
		try {
			this.backgroundImages.add(new ZoomedImage(1.0, ImageIO.read(img)));
		} catch (IOException e) {
			System.err.println("Could not read zoom 1 background image: " + img);
			return;
		}

		this.backgroundImageFile = img;

		// Computes the pattern regex for the other image names
		String prefix, suffix;

		String name = img.getName();
		int idx_dot = name.lastIndexOf('.');
		if (idx_dot == -1) {
			prefix = name;
			suffix = "";
		} else {
			prefix = name.substring(0, idx_dot);
			suffix = name.substring(idx_dot);
		}

		// In case the main image name include a zoom number, we remove it from the prefix
		prefix = prefix.replaceFirst("@0*1(\\.0*)?$", "");

		String numberRegex = "(\\d*\\.?\\d)";
		Pattern pattern = Pattern.compile(prefix + "@" + numberRegex + suffix);

		// Adds an image for each matching image file in the directory
		File[] dirContent = img.getParentFile().listFiles();
		for (File f : dirContent) {
			String filename = f.getName();
			Matcher matcher = pattern.matcher(filename);
			if (matcher.find()) {
				double zoom = Double.parseDouble(matcher.group(1));

				if (zoom != 0.0 && zoom != 1.0) {
					System.err.println("Found background image at zoom " + zoom);
					BufferedImage bufImg;
					try {
						bufImg = ImageIO.read(f);
						this.backgroundImages.add(new ZoomedImage(zoom, bufImg));
					} catch (IOException e) {
						System.err.println("Could not read background image: " + f);
						e.printStackTrace();
					}
				}
			}
		}
		// Computes the shifted zooms to a zoom between two successive zooms
		ZoomedImage a, b;
		Iterator<ZoomedImage> i = this.backgroundImages.iterator();

		a = i.next();
		a.shiftedZoom = 0.0;
		while (i.hasNext()) {
			b = i.next();
			b.shiftedZoom = a.zoom + ((b.zoom - a.zoom) / 3.0);
			System.err.println("Shifted zoom for zoom " + b.zoom + " = " + b.shiftedZoom);
			a = b;
		}

		// Initializes the current background image
		this.currentBackgroundImage = getBackgroundImage();
	}

	//-------------------------------------------------------------------------
	/**
	 * Gives the main background image (at zoom 1)
	 *
	 * @return the image
	 */
	private BufferedImage getBackgroundImage() {
		for (ZoomedImage zi : this.backgroundImages) {
			if (zi.zoom == 1.00) {
				return zi.image;
			}
		}
		return null;
	}

	//-------------------------------------------------------------------------
	// Inner Classes
	//-------------------------------------------------------------------------
	private class ZoomedImage implements Comparable<ZoomedImage> {

		double zoom;
		double shiftedZoom;
		BufferedImage image;

		ZoomedImage(double z, BufferedImage i) {
			this.zoom = z;
			this.image = i;

		}

		@Override
		public int compareTo(ZoomedImage other) {
			if (zoom == other.zoom) {
				return 0;
			}
			return (zoom > other.zoom ? 1 : -1);
		}
	}

	//-------------------------------------------------------------------------
	private class BackLayerRenderer implements LayerRenderer {

		protected double currentZoom;    // the current zoom factor
		private final Font font;         // the font for the time display

		//---------------------------------------------------------------------
		public BackLayerRenderer() {
			this.currentZoom = 1;
			this.font = makeFont();
		}

		//---------------------------------------------------------------------
		@Override
		public void render(Graphics2D graphics, GraphicGraph graph,
		                   double px2Gu, int widthPx, int heightPx,
		                   double minXGu, double minYGu,
		                   double maxXGu, double maxYGu) {

			lastRender = System.currentTimeMillis();
			computeDimensions(px2Gu, widthPx, heightPx, minXGu, minYGu, maxXGu, maxYGu);
			updateZoom();
			drawBackground(graphics);
			drawTransferEdges(graphics);
			drawTime(graphics);
		}

		//---------------------------------------------------------------------
		protected void drawBackground(Graphics2D graphics) {
			graphics.setColor(Color.white);
			graphics.fillRect(0, 0, widthPx, heightPx);

			if (backgroundImageFile != null) {
				double sx = (double) width / currentBackgroundImage.getWidth();
				double sy = (double) height / currentBackgroundImage.getHeight();

				AffineTransform transform = new AffineTransform();
				transform.setToTranslation(deltaX, deltaY);
				transform.scale(sx, sy);

				graphics.drawImage(currentBackgroundImage, transform, null);
			}

			if (backgroungGraph != null) {
				graphics.setColor(Color.gray);
				Iterator<Edge> iterator = backgroungGraph.getEdgeIterator();
				while (iterator.hasNext()) {
					Edge edge = iterator.next();
					Node node0 = edge.getNode0();
					Node node1 = edge.getNode1();
					CoordCar coord0 = getCoord(node0);
					CoordCar coord1 = getCoord(node1);
					graphics.drawLine((int) coord0.x, (int) coord0.y, (int) coord1.x, (int) coord1.y);
				}
			}

		}

		private void drawTransferEdges(Graphics2D graphics) {
			Stroke previousStroke = graphics.getStroke();
			Color previousColor = graphics.getColor();

			graphics.setColor(new Color(255, 176, 0, 190));
			graphics.setStroke(new BasicStroke(28f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));

			Iterator<Edge> iterator = oppNetGraph.getEdgeIterator();
			while (iterator.hasNext()) {
				Edge edge = iterator.next();
				if (edge instanceof OppEdge && hasTransferTag((OppEdge) edge)) {
					CoordCar coord0 = getCoord(edge.getNode0());
					CoordCar coord1 = getCoord(edge.getNode1());
					graphics.drawLine((int) coord0.x, (int) coord0.y, (int) coord1.x, (int) coord1.y);
				}
			}

			graphics.setStroke(previousStroke);
			graphics.setColor(previousColor);
		}

		private boolean hasTransferTag(OppEdge edge) {
			String tag = edge.getTag();
			if (tag == null) {
				return false;
			}
			for (String value : tag.split(",")) {
				if ("TRANSFER".equals(value.trim())) {
					return true;
				}
			}
			return false;
		}

		//---------------------------------------------------------------------
		protected boolean updateZoom() {
			double newZoom = 1.0 / camera.getViewPercent();
			if (currentZoom != newZoom) {
				currentZoom = newZoom;
				//                font = makeFont();
				if (backgroundImageFile != null) {
					updateBackgroundImage();
				}
				return true;
			}
			return false;
		}

		//---------------------------------------------------------------------
		/**
		 * Obtains the background image adequate for a current zoom factor
		 */
		private void updateBackgroundImage() {

			// Search, in reverse order, for the first shifted zoom greater
			// than the one passed as parameter
			// It is assumed that the list has got at least one entry
			// The lower entry has a shifted zoom equals to 0.0
			Iterator<ZoomedImage> i = backgroundImages.descendingIterator();
			while (i.hasNext()) {
				ZoomedImage zi = i.next();
				if (currentZoom >= zi.shiftedZoom) {
					System.err.println("->  background at zoom " + zi.zoom);
					currentBackgroundImage = zi.image;
					return;
				}
			}
		}

		//---------------------------------------------------------------------
		protected void computeDimensions(double px2Gu, int widthPx, int heightPx,
		                                 double minXGu, double minYGu,
		                                 double maxXGu, double maxYGu) {

			OppNetFrame.this.px2Gu = px2Gu;
			OppNetFrame.this.widthPx = widthPx;
			OppNetFrame.this.heightPx = heightPx;

			double areaCenterX, areaCenterY;
			if (viewportArea != null) {
				width = (double) viewportArea.width * px2Gu;
				height = (double) viewportArea.height * px2Gu;
				deltaX = (widthPx - width) / 2;
				deltaY = (heightPx - height) / 2;
				areaCenterX = (viewportArea.x + (viewportArea.width / 2)) * px2Gu;
				areaCenterY = (viewportArea.y + (viewportArea.height / 2)) * px2Gu;
			} else {
				width = widthPx;
				height = heightPx;
				deltaX = 0;
				deltaY = 0;
				areaCenterX = widthPx / 2;
				areaCenterY = heightPx / 2;
			}

			deltaX += areaCenterX - camera.getViewCenter().x * px2Gu;
			deltaY -= areaCenterY - camera.getViewCenter().y * px2Gu;
		}

		//---------------------------------------------------------------------
		protected void drawTime(Graphics2D g2d) {
			if (timeCorner != null) {
				Rectangle target = new Rectangle(0, 0, (int) widthPx, (int) heightPx);

				TitleBlock timeBlock = new TitleBlock(g2d, target, timeCorner, "00:00:00", font, timeFgColor, timeBgColor);
				timeBlock.draw(getCurrentTime());
			}
			if (elapsedLabel != null) {
				elapsedLabel.setText(getElapsedTime());
			}
		}

		//---------------------------------------------------------------------
		private Font makeFont() {
			String fname = timeFont.getFontName();
			int fstyle = timeFont.getStyle();
			int fsize = (int) Math.round(timeFont.getSize() * currentZoom);  // zoom font
			return new Font(fname, fstyle, fsize);
		}

	}
}
